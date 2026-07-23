// Package wireguard implements an outbound-only userspace WireGuard client.
package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	appoutbound "github.com/eugene/bypasscore/app/outbound"
	"github.com/eugene/bypasscore/common/errors"
	bcnet "github.com/eugene/bypasscore/common/net"
	"github.com/eugene/bypasscore/common/wgkey"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	defaultMTU         = 1420
	defaultDialTimeout = 10 * time.Second
)

var defaultAddresses = []string{"172.16.0.2/32", "fd59:7153:2388:b5fd:0000:0000:0000:0002/128"}

// Handler owns one WireGuard device and its userspace IP stack.
type Handler struct {
	tag    string
	config *appoutbound.WireGuardConfig

	initMu  sync.Mutex
	tun     tun.Device
	net     *netstack.Net
	device  *device.Device
	hasIPv4 bool
	hasIPv6 bool

	closeOnce sync.Once
	closed    bool
	mu        sync.RWMutex
}

// New creates a lazily initialized WireGuard outbound.
func New(tag string, config *appoutbound.WireGuardConfig) *Handler {
	return &Handler{tag: tag, config: config}
}

func (h *Handler) Tag() string { return h.tag }

// Dial initializes the device on first use and opens TCP or UDP through it.
func (h *Handler) Dial(ctx context.Context, dest bcnet.Destination) (net.Conn, error) {
	if err := h.ensureInitialized(ctx); err != nil {
		return nil, errors.New("wireguard[", h.tag, "] initialize failed").Base(err)
	}
	h.mu.RLock()
	tnet, closed, hasIPv4, hasIPv6 := h.net, h.closed, h.hasIPv4, h.hasIPv6
	h.mu.RUnlock()
	if closed || tnet == nil {
		return nil, errors.New("wireguard[", h.tag, "] is closed")
	}

	dialCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, defaultDialTimeout)
		defer cancel()
	}
	address, err := numericDestination(dialCtx, dest, hasIPv4, hasIPv6)
	if err != nil {
		return nil, err
	}
	connection, err := tnet.DialContext(dialCtx, dest.Network.SystemString(), address)
	if err != nil {
		return nil, errors.New("wireguard[", h.tag, "] dial ", address, " failed").Base(err)
	}
	return connection, nil
}

func numericDestination(ctx context.Context, dest bcnet.Destination, hasIPv4, hasIPv6 bool) (string, error) {
	// common/net renders literal IPv6 addresses with brackets for display.
	// netip.ParseAddr and net.JoinHostPort expect the host itself unbracketed.
	host := strings.Trim(dest.Address.String(), "[]")
	if dest.Address.Family().IsDomain() {
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return "", errors.New("resolve WireGuard target ", host).Base(err)
		}
		if len(addresses) == 0 {
			return "", errors.New("no address for WireGuard target ", host)
		}
		address, ok := preferredAddress(addresses, hasIPv4, hasIPv6)
		if !ok {
			return "", errors.New("no address with a configured WireGuard address family for ", host)
		}
		host = address.String()
	} else if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if (ip.Is4() && !hasIPv4) || (ip.Is6() && !hasIPv6) {
			return "", errors.New("WireGuard outbound ", dest, " has no matching local address family")
		}
		host = ip.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(dest.Port))), nil
}

func (h *Handler) ensureInitialized(ctx context.Context) error {
	h.mu.RLock()
	ready, closed := h.net != nil, h.closed
	h.mu.RUnlock()
	if ready {
		return nil
	}
	if closed {
		return errors.New("outbound is closed")
	}
	h.initMu.Lock()
	defer h.initMu.Unlock()
	h.mu.RLock()
	ready, closed = h.net != nil, h.closed
	h.mu.RUnlock()
	if ready {
		return nil
	}
	if closed {
		return errors.New("outbound is closed")
	}
	// Only a successful initialization is installed. DNS or endpoint failures
	// therefore remain retryable by later connections.
	return h.initialize(ctx)
}

func (h *Handler) initialize(ctx context.Context) error {
	if h.config == nil {
		return errors.New("missing wireguard config")
	}
	private, err := wgkey.Parse(h.config.SecretKey)
	if err != nil {
		return err
	}
	if wgkey.IsZero(private) {
		return errors.New("secretKey must not be all zero")
	}
	addresses := h.config.Address
	if len(addresses) == 0 {
		addresses = defaultAddresses
	}
	localAddresses := make([]netip.Addr, 0, len(addresses))
	hasIPv4, hasIPv6 := false, false
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("invalid WireGuard address %q: %w", value, err)
		}
		address := prefix.Addr().Unmap()
		localAddresses = append(localAddresses, address)
		hasIPv4 = hasIPv4 || address.Is4()
		hasIPv6 = hasIPv6 || address.Is6()
	}
	mtu := h.config.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	tunDevice, virtualNet, err := netstack.CreateNetTUN(localAddresses, nil, mtu)
	if err != nil {
		return err
	}
	wgDevice := device.NewDevice(tunDevice, conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(format string, args ...any) {
			errors.LogDebug(context.Background(), "wireguard[", h.tag, "]: ", fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			errors.LogError(context.Background(), "wireguard[", h.tag, "]: ", fmt.Sprintf(format, args...))
		},
	})
	fail := func(cause error) error {
		wgDevice.Close()
		_ = tunDevice.Close()
		return cause
	}

	var ipc strings.Builder
	ipc.WriteString("private_key=")
	ipc.WriteString(wgkey.Hex(private))
	ipc.WriteByte('\n')
	ipc.WriteString("replace_peers=true\n")
	for index, peer := range h.config.Peers {
		public, err := wgkey.Parse(peer.PublicKey)
		if err != nil {
			return fail(fmt.Errorf("peer[%d] publicKey: %w", index, err))
		}
		endpoint, err := resolveEndpoint(ctx, peer.Endpoint)
		if err != nil {
			return fail(fmt.Errorf("peer[%d] endpoint: %w", index, err))
		}
		ipc.WriteString("public_key=")
		ipc.WriteString(wgkey.Hex(public))
		ipc.WriteByte('\n')
		if peer.PreSharedKey != "" {
			psk, err := wgkey.Parse(peer.PreSharedKey)
			if err != nil {
				return fail(fmt.Errorf("peer[%d] preSharedKey: %w", index, err))
			}
			ipc.WriteString("preshared_key=")
			ipc.WriteString(wgkey.Hex(psk))
			ipc.WriteByte('\n')
		}
		ipc.WriteString("endpoint=")
		ipc.WriteString(endpoint)
		ipc.WriteByte('\n')
		allowed := peer.AllowedIPs
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		for _, prefix := range allowed {
			ipc.WriteString("allowed_ip=")
			ipc.WriteString(strings.TrimSpace(prefix))
			ipc.WriteByte('\n')
		}
		if peer.KeepAlive != 0 {
			fmt.Fprintf(&ipc, "persistent_keepalive_interval=%d\n", peer.KeepAlive)
		}
	}
	if err := wgDevice.IpcSet(ipc.String()); err != nil {
		return fail(err)
	}
	if err := wgDevice.Up(); err != nil {
		return fail(err)
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return fail(errors.New("closed during initialization"))
	}
	h.tun, h.net, h.device = tunDevice, virtualNet, wgDevice
	h.hasIPv4, h.hasIPv6 = hasIPv4, hasIPv6
	h.mu.Unlock()
	return nil
}

func resolveEndpoint(ctx context.Context, endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		return "", err
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", errors.New("invalid port").Base(err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(ip.Unmap().String(), port), nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(addresses) == 0 {
		return "", errors.New("no address for ", host)
	}
	address, ok := preferredAddress(addresses, true, true)
	if !ok {
		return "", errors.New("no usable address for ", host)
	}
	return net.JoinHostPort(address.String(), port), nil
}

func preferredAddress(addresses []netip.Addr, allowIPv4, allowIPv6 bool) (netip.Addr, bool) {
	// Prefer IPv4 for an endpoint/target when both families are usable. This is
	// the least surprising default on dual-stack OpenWrt installations, while
	// still falling back to IPv6-only configurations.
	for _, wantIPv4 := range []bool{true, false} {
		for _, address := range addresses {
			address = address.Unmap()
			if address.Is4() == wantIPv4 &&
				((address.Is4() && allowIPv4) || (address.Is6() && allowIPv6)) {
				return address, true
			}
		}
	}
	return netip.Addr{}, false
}

// Close tears down the WireGuard device and userspace network stack.
func (h *Handler) Close() error {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		wgDevice, tunDevice := h.device, h.tun
		h.device, h.tun, h.net = nil, nil, nil
		h.hasIPv4, h.hasIPv6 = false, false
		h.mu.Unlock()
		if wgDevice != nil {
			wgDevice.Close()
		} else if tunDevice != nil {
			_ = tunDevice.Close()
		}
	})
	return nil
}
