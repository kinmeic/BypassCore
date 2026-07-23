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

	"github.com/eugene/bypasscore/app/dialer"
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
		return nil, errors.New("wireguard[", h.tag, "] dial ", address, " failed; ", h.handshakeSummary()).Base(err)
	}
	return connection, nil
}

// ProbeHandshake sends one packet through the userspace tunnel and waits for
// the WireGuard peer handshake state to become current. It verifies the UDP
// carrier itself and intentionally does not depend on a public TCP/HTTP target.
func (h *Handler) ProbeHandshake(ctx context.Context) (dialer.HandshakeResult, error) {
	probeCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, defaultDialTimeout)
		defer cancel()
	}
	if err := h.ensureInitialized(probeCtx); err != nil {
		return dialer.HandshakeResult{}, errors.New("wireguard[", h.tag, "] initialize failed").Base(err)
	}
	h.mu.RLock()
	tnet, wgDevice, closed, hasIPv4 := h.net, h.device, h.closed, h.hasIPv4
	h.mu.RUnlock()
	if closed || tnet == nil || wgDevice == nil {
		return dialer.HandshakeResult{}, errors.New("wireguard[", h.tag, "] is closed")
	}

	probeAddress, err := h.handshakeProbeAddress(hasIPv4)
	if err != nil {
		return dialer.HandshakeResult{}, err
	}
	started := time.Now()
	connection, err := tnet.DialContext(probeCtx, "udp", probeAddress)
	if err != nil {
		return dialer.HandshakeResult{}, errors.New("wireguard[", h.tag, "] UDP probe failed; ", h.handshakeSummary()).Base(err)
	}
	// A syntactically valid DNS query is used only to make the netstack emit an
	// inner packet. A DNS response is not required: peer handshake state is the
	// authoritative result.
	_ = connection.SetWriteDeadline(deadlineOr(probeCtx, started.Add(defaultDialTimeout)))
	_, writeErr := connection.Write([]byte{
		0x42, 0x43, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
	})
	_ = connection.Close()
	if writeErr != nil {
		return dialer.HandshakeResult{}, errors.New("wireguard[", h.tag, "] UDP probe write failed; ", h.handshakeSummary()).Base(writeErr)
	}

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		handshake, stateErr := latestHandshake(wgDevice)
		if stateErr != nil {
			return dialer.HandshakeResult{}, errors.New("wireguard[", h.tag, "] read handshake state failed").Base(stateErr)
		}
		if !handshake.IsZero() && time.Since(handshake) <= 3*time.Minute {
			return dialer.HandshakeResult{Latency: time.Since(started), LastHandshake: handshake}, nil
		}
		select {
		case <-probeCtx.Done():
			return dialer.HandshakeResult{}, errors.New("wireguard[", h.tag, "] UDP handshake timed out; ", h.handshakeSummary()).Base(probeCtx.Err())
		case <-ticker.C:
		}
	}
}

func (h *Handler) handshakeProbeAddress(preferIPv4 bool) (string, error) {
	var fallback netip.Addr
	hasAllowedIP := false
	for _, peer := range h.config.Peers {
		for _, allowed := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(allowed))
			if err != nil {
				continue
			}
			hasAllowedIP = true
			candidate := prefix.Addr().Unmap()
			if prefix.Bits() < candidate.BitLen() {
				candidate = candidate.Next()
			}
			if !candidate.IsValid() {
				continue
			}
			if !fallback.IsValid() {
				fallback = candidate
			}
			if candidate.Is4() == preferIPv4 {
				return net.JoinHostPort(candidate.String(), "53"), nil
			}
		}
	}
	if !hasAllowedIP {
		if preferIPv4 {
			return "1.1.1.1:53", nil
		}
		return "[2606:4700:4700::1111]:53", nil
	}
	if fallback.IsValid() {
		return net.JoinHostPort(fallback.String(), "53"), nil
	}
	return "", errors.New("wireguard[", h.tag, "] has no allowed IP for UDP handshake probe")
}

func deadlineOr(ctx context.Context, fallback time.Time) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return fallback
}

func latestHandshake(wgDevice *device.Device) (time.Time, error) {
	state, err := wgDevice.IpcGet()
	if err != nil {
		return time.Time{}, err
	}
	var latest time.Time
	for _, line := range strings.Split(state, "\n") {
		if !strings.HasPrefix(line, "last_handshake_time_sec=") {
			continue
		}
		seconds, parseErr := strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_sec="), 10, 64)
		if parseErr == nil && seconds > 0 {
			value := time.Unix(seconds, 0)
			if value.After(latest) {
				latest = value
			}
		}
	}
	return latest, nil
}

func (h *Handler) handshakeSummary() string {
	h.mu.RLock()
	wgDevice := h.device
	h.mu.RUnlock()
	if wgDevice == nil {
		return "WireGuard device is not initialized"
	}
	handshake, err := latestHandshake(wgDevice)
	if err != nil {
		return "WireGuard handshake state is unavailable"
	}
	if handshake.IsZero() {
		return "WireGuard handshake has never completed (check endpoint UDP reachability, endpoint public key, pre-shared key, local address, and server peer configuration)"
	}
	return fmt.Sprintf("last WireGuard handshake was %s ago", time.Since(handshake).Round(time.Second))
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
