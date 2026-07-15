package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	mode := flag.String("mode", "", "serve, socks, tcp-client, udp-client, flood")
	listen := flag.String("listen", "", "listen address")
	tcpPorts := flag.String("tcp-ports", "", "comma-separated TCP ports")
	udpPorts := flag.String("udp-ports", "", "comma-separated UDP ports")
	target := flag.String("target", "", "target host:port")
	payload := flag.String("payload", "netns-ok", "test payload")
	startPort := flag.Int("start-port", 20000, "flood start port")
	count := flag.Int("count", 1200, "flood destination count")
	flag.Parse()

	var err error
	switch *mode {
	case "serve":
		err = serve(*listen, *tcpPorts, *udpPorts)
	case "socks":
		err = serveSOCKS(*listen)
	case "tcp-client":
		err = tcpClient(*target, []byte(*payload))
	case "udp-client":
		err = udpClient(*target, []byte(*payload))
	case "flood":
		err = flood(*target, *startPort, *count)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func ports(value string) ([]int, error) {
	var result []int
	for _, item := range strings.Split(value, ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", item)
		}
		result = append(result, port)
	}
	return result, nil
}

func serve(host, tcpList, udpList string) error {
	tcp, err := ports(tcpList)
	if err != nil {
		return err
	}
	udp, err := ports(udpList)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	for _, port := range tcp {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					buf := make([]byte, 32*1024)
					for {
						n, err := conn.Read(buf)
						if n > 0 {
							if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
								return
							}
						}
						if err != nil {
							return
						}
					}
				}()
			}
		}()
	}
	for _, port := range udp {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: port})
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 65535)
			for {
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, _ = conn.WriteToUDP(buf[:n], addr)
			}
		}()
	}
	wg.Wait()
	return nil
}

func tcpClient(target string, payload []byte) error {
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != string(payload) {
		return fmt.Errorf("TCP echo mismatch: %q", got)
	}
	fmt.Printf("tcp peer=%s payload=%s\n", conn.RemoteAddr(), got)
	return nil
}

func udpClient(target string, payload []byte) error {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	n, err := conn.Read(got)
	if err != nil {
		return err
	}
	if string(got[:n]) != string(payload) {
		return fmt.Errorf("UDP echo mismatch: %q", got[:n])
	}
	// A connected UDP socket accepts only packets from target. Successful read
	// therefore verifies that transparent replies restored the original source.
	fmt.Printf("udp peer=%s payload=%s\n", conn.RemoteAddr(), got[:n])
	return nil
}

func flood(host string, start, count int) error {
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid flood target IP %q", host)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return err
	}
	defer conn.Close()
	for i := 0; i < count; i++ {
		if _, err := conn.WriteToUDP([]byte{byte(i)}, &net.UDPAddr{IP: ip, Port: start + i}); err != nil {
			return err
		}
	}
	return nil
}

func serveSOCKS(address string) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSOCKS(conn, address)
	}
}

func handleSOCKS(control net.Conn, listenAddress string) {
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(control, header); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(control, methods); err != nil {
		return
	}
	if _, err := control.Write([]byte{5, 0}); err != nil {
		return
	}
	command := make([]byte, 3)
	if _, err := io.ReadFull(control, command); err != nil || command[0] != 5 || command[1] != 3 {
		return
	}
	if _, err := readAddress(control); err != nil {
		return
	}
	host, _, _ := net.SplitHostPort(listenAddress)
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		return
	}
	defer relay.Close()
	bound := relay.LocalAddr().(*net.UDPAddr)
	response := []byte{5, 0, 0}
	response = appendAddress(response, bound)
	if _, err := control.Write(response); err != nil {
		return
	}
	_ = control.SetDeadline(time.Time{})
	go relaySOCKSUDP(relay)
	_, _ = io.Copy(io.Discard, control)
}

func relaySOCKSUDP(relay *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, client, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue
		}
		target, offset, err := parseAddress(buf[3:n])
		if err != nil {
			continue
		}
		upstream, err := net.DialUDP("udp", nil, target)
		if err != nil {
			continue
		}
		_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = upstream.Write(buf[3+offset : n]); err == nil {
			reply := make([]byte, 65535)
			if rn, _, readErr := upstream.ReadFromUDP(reply); readErr == nil {
				packet := []byte{0, 0, 0}
				packet = appendAddress(packet, target)
				packet = append(packet, reply[:rn]...)
				_, _ = relay.WriteToUDP(packet, client)
			}
		}
		upstream.Close()
	}
}

func readAddress(r io.Reader) (*net.UDPAddr, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return nil, err
	}
	var host string
	switch typ[0] {
	case 1:
		buf := make([]byte, 4)
		_, _ = io.ReadFull(r, buf)
		host = net.IP(buf).String()
	case 4:
		buf := make([]byte, 16)
		_, _ = io.ReadFull(r, buf)
		host = net.IP(buf).String()
	case 3:
		var length [1]byte
		_, _ = io.ReadFull(r, length[:])
		buf := make([]byte, int(length[0]))
		_, _ = io.ReadFull(r, buf)
		host = string(buf)
	default:
		return nil, fmt.Errorf("bad address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))))
}

func parseAddress(data []byte) (*net.UDPAddr, int, error) {
	r := strings.NewReader(string(data))
	addr, err := readAddress(r)
	return addr, len(data) - r.Len(), err
}

func appendAddress(dst []byte, addr *net.UDPAddr) []byte {
	if ip := addr.IP.To4(); ip != nil {
		dst = append(dst, 1)
		dst = append(dst, ip...)
	} else {
		dst = append(dst, 4)
		dst = append(dst, addr.IP.To16()...)
	}
	return binary.BigEndian.AppendUint16(dst, uint16(addr.Port))
}
