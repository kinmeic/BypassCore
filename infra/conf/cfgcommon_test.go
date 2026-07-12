package conf

import (
	"encoding/json"
	"testing"
)

// --- StringList ---

func TestStringList_FromArray(t *testing.T) {
	var sl StringList
	if err := json.Unmarshal([]byte(`["a","b","c"]`), &sl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if sl.Len() != 3 || sl[0] != "a" || sl[2] != "c" {
		t.Errorf("StringList = %v", sl)
	}
}

func TestStringList_FromCSV(t *testing.T) {
	var sl StringList
	if err := json.Unmarshal([]byte(`"a,b,c"`), &sl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if sl.Len() != 3 {
		t.Errorf("CSV StringList = %v, want 3 items", sl)
	}
}

func TestStringList_FromSingleString(t *testing.T) {
	var sl StringList
	if err := json.Unmarshal([]byte(`"only"`), &sl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if sl.Len() != 1 || sl[0] != "only" {
		t.Errorf("single StringList = %v", sl)
	}
}

func TestStringList_Invalid(t *testing.T) {
	var sl StringList
	if err := json.Unmarshal([]byte(`123`), &sl); err == nil {
		t.Error("number should fail to parse as StringList")
	}
}

// --- NetworkList ---

func TestNetworkList_FromArray(t *testing.T) {
	var nl NetworkList
	if err := json.Unmarshal([]byte(`["tcp","udp"]`), &nl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := nl.Build()
	if len(got) != 2 {
		t.Errorf("Build len = %d, want 2", len(got))
	}
}

func TestNetworkList_FromCSV(t *testing.T) {
	var nl NetworkList
	if err := json.Unmarshal([]byte(`"tcp,udp"`), &nl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := nl.Build()
	if len(got) != 2 {
		t.Errorf("Build len = %d, want 2", len(got))
	}
}

func TestNetworkList_BuildUnknown(t *testing.T) {
	nl := NetworkList{Network("fancy")}
	got := nl.Build()
	if len(got) != 1 || got[0].String() != "Unknown" {
		t.Errorf("unknown network Build = %v", got)
	}
}

func TestNetwork_Build_Cases(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"tcp", "TCP"},
		{"TCP", "TCP"},
		{"udp", "UDP"},
		{"unix", "UNIX"},
		{"bogus", "Unknown"},
	}
	for _, c := range cases {
		if got := Network(c.in).Build().String(); got != c.want {
			t.Errorf("Network(%q).Build() = %s, want %s", c.in, got, c.want)
		}
	}
}

// --- PortRange / PortList ---

func TestPortRange_SingleInt(t *testing.T) {
	var pr PortRange
	if err := json.Unmarshal([]byte(`443`), &pr); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pr.From != 443 || pr.To != 443 {
		t.Errorf("single port range = %v, want {443 443}", pr)
	}
}

func TestPortRange_RangeString(t *testing.T) {
	var pr PortRange
	if err := json.Unmarshal([]byte(`"1000-2000"`), &pr); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pr.From != 1000 || pr.To != 2000 {
		t.Errorf("range = %v, want {1000 2000}", pr)
	}
}

func TestPortRange_RejectsInverted(t *testing.T) {
	var pr PortRange
	if err := json.Unmarshal([]byte(`"2000-1000"`), &pr); err == nil {
		t.Error("inverted range should be rejected")
	}
}

func TestPortRange_RejectsTooLarge(t *testing.T) {
	var pr PortRange
	if err := json.Unmarshal([]byte(`"80-70000"`), &pr); err == nil {
		t.Error("range exceeding 65535 should be rejected")
	}
}

func TestPortRange_StringRoundTrip(t *testing.T) {
	pr := PortRange{From: 443, To: 443}
	if got := pr.String(); got != "443" {
		t.Errorf("single String = %q, want 443", got)
	}
	pr2 := PortRange{From: 80, To: 90}
	if got := pr2.String(); got != "80-90" {
		t.Errorf("range String = %q, want 80-90", got)
	}
}

func TestPortList_FromString(t *testing.T) {
	var pl PortList
	if err := json.Unmarshal([]byte(`"80,443,1000-2000"`), &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(pl.Range) != 3 {
		t.Fatalf("want 3 ranges, got %d", len(pl.Range))
	}
	built := pl.Build()
	// built.Ports() expands to enumerate all ports.
	ports := built.Ports()
	if len(ports) != 1+1+1001 {
		t.Errorf("expanded ports count = %d, want %d", len(ports), 1+1+1001)
	}
}

func TestPortList_FromNumber(t *testing.T) {
	var pl PortList
	if err := json.Unmarshal([]byte(`53`), &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(pl.Range) != 1 || pl.Range[0].From != 53 || pl.Range[0].To != 53 {
		t.Errorf("number port list = %v", pl.Range)
	}
}

func TestPortList_FromArray(t *testing.T) {
	// PortList UnmarshalJSON doesn't directly accept arrays, only string/number.
	// Verify a plain number works and bad input fails.
	var pl PortList
	if err := json.Unmarshal([]byte(`"not-a-port"`), &pl); err == nil {
		t.Error("invalid port string should be rejected")
	}
}

// --- Duration ---

func TestDuration_FromString(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"1s"`), &d); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if int64(d) != int64(1_000_000_000) {
		t.Errorf("1s = %d ns, want 1e9", int64(d))
	}
}

func TestDuration_FromNumber(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`500000000`), &d); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if int64(d) != 500_000_000 {
		t.Errorf("number = %d, want 5e8", int64(d))
	}
}

func TestDuration_Invalid(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"not-a-duration"`), &d); err == nil {
		t.Error("invalid duration string should be rejected")
	}
}

// --- Address ---

func TestAddress_Unmarshal(t *testing.T) {
	var a Address
	if err := json.Unmarshal([]byte(`"1.2.3.4"`), &a); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !a.Family().IsIPv4() {
		t.Errorf("1.2.3.4 family = %v, want IPv4", a.Family())
	}

	var b Address
	if err := json.Unmarshal([]byte(`"example.com"`), &b); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !b.Family().IsDomain() {
		t.Errorf("example.com family = %v, want Domain", b.Family())
	}
}

func TestAddress_MarshalRoundTrip(t *testing.T) {
	a := Address{}
	if err := json.Unmarshal([]byte(`"10.0.0.1"`), &a); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := json.Marshal(&a)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != `"10.0.0.1"` {
		t.Errorf("round-trip = %s, want \"10.0.0.1\"", string(out))
	}
}

func TestAddress_NilAccessors(t *testing.T) {
	var a *Address
	if got := a.String(); got != "<nil>" {
		t.Errorf("nil String = %q, want <nil>", got)
	}
	if got := a.Family(); !got.IsDomain() {
		t.Errorf("nil Family = %v, want Domain (default)", got)
	}
}
