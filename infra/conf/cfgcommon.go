// Package conf provides JSON parsing for the routing configuration.
package conf

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/eugene/bypasscore/common/errors"
	"github.com/eugene/bypasscore/common/net"
)

// StringList accepts either a JSON array of strings or a comma-separated string.
type StringList []string

// Address wraps a parsed network address (IP or domain).
type Address struct {
	net.Address
}

// String returns the textual form.
func (v *Address) String() string {
	if v == nil {
		return "<nil>"
	}
	return v.Address.String()
}

// Family returns the address family.
func (v *Address) Family() net.AddressFamily {
	if v == nil {
		return net.AddressFamilyDomain
	}
	return v.Address.Family()
}

// MarshalJSON renders the address as its string form.
func (v *Address) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.Address.String())
}

// UnmarshalJSON parses an address string.
func (v *Address) UnmarshalJSON(data []byte) error {
	var rawStr string
	if err := json.Unmarshal(data, &rawStr); err != nil {
		return errors.New("invalid address: ", string(data)).Base(err)
	}
	v.Address = net.ParseAddress(rawStr)
	return nil
}

// NewStringList wraps a slice as a StringList pointer.
func NewStringList(raw []string) *StringList {
	list := StringList(raw)
	return &list
}

// Len returns the number of entries.
func (v StringList) Len() int { return len(v) }

// UnmarshalJSON accepts ["a","b"] or "a,b".
func (v *StringList) UnmarshalJSON(data []byte) error {
	var strarray []string
	if err := json.Unmarshal(data, &strarray); err == nil {
		*v = *NewStringList(strarray)
		return nil
	}
	var rawstr string
	if err := json.Unmarshal(data, &rawstr); err == nil {
		strlist := strings.Split(rawstr, ",")
		*v = *NewStringList(strlist)
		return nil
	}
	return errors.New("unknown format of a string list: " + string(data))
}

// Network is a network type string ("tcp"/"udp"/"unix").
type Network string

// Build converts the network string to net.Network.
func (v Network) Build() net.Network {
	switch strings.ToLower(string(v)) {
	case "tcp":
		return net.Network_TCP
	case "udp":
		return net.Network_UDP
	case "unix":
		return net.Network_UNIX
	default:
		return net.Network_Unknown
	}
}

// NetworkList accepts ["tcp","udp"] or "tcp,udp".
type NetworkList []Network

// UnmarshalJSON implements encoding/json.Unmarshaler.UnmarshalJSON.
func (v *NetworkList) UnmarshalJSON(data []byte) error {
	var strarray []Network
	if err := json.Unmarshal(data, &strarray); err == nil {
		nl := NetworkList(strarray)
		*v = nl
		return v.validate()
	}
	var rawstr Network
	if err := json.Unmarshal(data, &rawstr); err == nil {
		strlist := strings.Split(string(rawstr), ",")
		nl := make(NetworkList, len(strlist))
		for idx, network := range strlist {
			nl[idx] = Network(network)
		}
		*v = nl
		return v.validate()
	}
	return errors.New("unknown format of a string list: " + string(data))
}

func (v NetworkList) validate() error {
	for _, network := range v {
		if network.Build() == net.Network_Unknown {
			return errors.New("unknown network: " + string(network))
		}
	}
	return nil
}

// Build converts the list to []net.Network. Defaults to TCP when nil.
func (v *NetworkList) Build() []net.Network {
	if v == nil {
		return []net.Network{net.Network_TCP}
	}
	list := make([]net.Network, 0, len(*v))
	for _, network := range *v {
		list = append(list, network.Build())
	}
	return list
}

// PortRange is a (possibly single) port range.
type PortRange struct {
	From uint32
	To   uint32
}

// Build converts to *net.PortRange.
func (v *PortRange) Build() *net.PortRange {
	return &net.PortRange{From: v.From, To: v.To}
}

func (port *PortRange) String() string {
	if port.From == port.To {
		return strconv.Itoa(int(port.From))
	}
	return fmt.Sprintf("%d-%d", port.From, port.To)
}

// MarshalJSON renders a single port or a "from-to" range.
func (v *PortRange) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

// UnmarshalJSON accepts a single int or a "from-to" string.
func (v *PortRange) UnmarshalJSON(data []byte) error {
	port, err := parseIntPort(data)
	if err == nil {
		v.From = uint32(port)
		v.To = uint32(port)
		return nil
	}
	from, to, err := parseJSONStringPort(data)
	if err == nil {
		v.From = uint32(from)
		v.To = uint32(to)
		if v.From > v.To || v.To > math.MaxUint16 {
			return errors.New("invalid port range ", v.From, " -> ", v.To)
		}
		return nil
	}
	return errors.New("invalid port range: ", string(data))
}

func parseIntPort(data []byte) (net.Port, error) {
	var intPort uint32
	err := json.Unmarshal(data, &intPort)
	if err != nil {
		return net.Port(0), err
	}
	return net.PortFromInt(intPort)
}

func parseStringPort(s string) (net.Port, net.Port, error) {
	pair := strings.SplitN(s, "-", 2)
	if len(pair) == 0 {
		return net.Port(0), net.Port(0), errors.New("invalid port range: ", s)
	}
	if len(pair) == 1 {
		port, err := net.PortFromString(pair[0])
		return port, port, err
	}
	fromPort, err := net.PortFromString(pair[0])
	if err != nil {
		return net.Port(0), net.Port(0), err
	}
	toPort, err := net.PortFromString(pair[1])
	if err != nil {
		return net.Port(0), net.Port(0), err
	}
	return fromPort, toPort, nil
}

func parseJSONStringPort(data []byte) (net.Port, net.Port, error) {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return net.Port(0), net.Port(0), err
	}
	return parseStringPort(s)
}

// PortList is a list of PortRange.
type PortList struct {
	Range []PortRange
}

// parseDuration parses a Go duration string (e.g. "1s", "500ms") into nanoseconds.
func parseDuration(s string) (int64, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	return int64(d), nil
}

// Build converts to *net.PortList.
func (list *PortList) Build() *net.PortList {
	portList := new(net.PortList)
	for _, r := range list.Range {
		portList.Range = append(portList.Range, r.Build())
	}
	return portList
}

// UnmarshalJSON accepts a string ("80,443" or "80-90" or "443"), a single
// number, or a JSON array of such entries.
func (list *PortList) UnmarshalJSON(data []byte) error {
	var entries []json.RawMessage
	if err := json.Unmarshal(data, &entries); err == nil {
		for _, entry := range entries {
			var part PortList
			if err := part.UnmarshalJSON(entry); err != nil {
				return err
			}
			list.Range = append(list.Range, part.Range...)
		}
		return nil
	}
	var listStr string
	var number uint32
	if err := json.Unmarshal(data, &listStr); err != nil {
		if err2 := json.Unmarshal(data, &number); err2 != nil {
			return errors.New("invalid port: ", string(data)).Base(err2)
		}
		listStr = strconv.FormatUint(uint64(number), 10)
	}
	rangelist := strings.Split(listStr, ",")
	for _, rangeStr := range rangelist {
		trimmed := strings.TrimSpace(rangeStr)
		if len(trimmed) == 0 {
			continue
		}
		if strings.Contains(trimmed, "-") {
			from, to, err := parseStringPort(trimmed)
			if err != nil {
				return errors.New("invalid port range: ", trimmed).Base(err)
			}
			list.Range = append(list.Range, PortRange{From: uint32(from), To: uint32(to)})
			continue
		}
		port, err := net.PortFromString(trimmed)
		if err != nil {
			return errors.New("invalid port: ", trimmed).Base(err)
		}
		list.Range = append(list.Range, PortRange{From: uint32(port), To: uint32(port)})
	}
	return nil
}
