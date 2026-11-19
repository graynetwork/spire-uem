package radius

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Vector computed independently with Python hashlib/hmac from RFC 5176 section 2.3.
const (
	vecRequestHex  = "28010040aa0b69aeab1705f6e673126c7154649d0107616c6963651f1361612d62622d63632d64642d65652d66665012c0d332eac10e4116f1cddbe457f9d795"
	vecResponseHex = "29010014d56b805a0125b0295fe425d3627dd6f8"
)

func TestEncodeRequest_MatchesIndependentVector(t *testing.T) {
	p := &Packet{Code: CodeDisconnectRequest, ID: 1, Attrs: []Attr{
		StringAttr(AttrUserName, "alice"), StringAttr(AttrCallingStationID, "aa-bb-cc-dd-ee-ff")}}
	raw, err := p.EncodeRequest([]byte("testing123"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(raw); got != vecRequestHex {
		t.Fatalf("request mismatch\n got %s\nwant %s", got, vecRequestHex)
	}
	if err := VerifyRequest(raw, []byte("testing123")); err != nil {
		t.Fatalf("own packet does not verify: %v", err)
	}
	// Response vector.
	want, _ := hex.DecodeString(vecResponseHex)
	got, _ := EncodeResponse(CodeDisconnectACK, 1, p.Authenticator, []byte("testing123"), nil)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("response mismatch\n got %x\nwant %x", got, want)
	}
	if _, err := VerifyResponse(want, p.Authenticator, []byte("testing123")); err != nil {
		t.Fatalf("vector response does not verify: %v", err)
	}
}

func TestVerifyRequest_RejectsTamperingAndWrongSecret(t *testing.T) {
	p := &Packet{Code: CodeDisconnectRequest, ID: 9, Attrs: []Attr{StringAttr(AttrUserName, "bob")}}
	raw, _ := p.EncodeRequest([]byte("s3cretvalue"))
	if err := VerifyRequest(raw, []byte("other-secret")); err == nil {
		t.Fatal("wrong secret must not verify")
	}
	for _, i := range []int{1, 8, 21, 24} { // id, authenticator, attribute bytes
		bad := append([]byte(nil), raw...)
		bad[i] ^= 0x01
		if err := VerifyRequest(bad, []byte("s3cretvalue")); err == nil {
			t.Fatalf("tampered byte %d must not verify", i)
		}
	}
	if _, err := VerifyResponse(raw, p.Authenticator, []byte("s3cretvalue")); err == nil {
		t.Fatal("a request must not verify as a response")
	}
}

func TestDecode_RejectsMalformed(t *testing.T) {
	for name, b := range map[string][]byte{
		"short":     {40, 1, 0, 10},
		"bad len":   append([]byte{40, 1, 0xff, 0xff}, make([]byte, 16)...),
		"attr len0": append([]byte{40, 1, 0, 22}, append(make([]byte, 16), 1, 0)...),
		"attr over": append([]byte{40, 1, 0, 22}, append(make([]byte, 16), 1, 9)...),
	} {
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestEncodeRequest_Limits(t *testing.T) {
	if _, err := (&Packet{Code: 40}).EncodeRequest(nil); err == nil {
		t.Fatal("empty secret must be refused")
	}
	long := make([]byte, 254)
	if _, err := (&Packet{Code: 40, Attrs: []Attr{{Type: 1, Value: long}}}).EncodeRequest([]byte("x")); err == nil {
		t.Fatal("oversize attribute must be refused")
	}
}

// ---- rlm_rest request parsing ----------------------------------------------------------

func TestParseRESTRequest_RealFreeRADIUSShape(t *testing.T) {
	body := `{"User-Name":{"type":"string","value":["aa:bb:cc:dd:ee:ff"]},
		"NAS-IP-Address":{"type":"ipaddr","value":["192.0.2.7"]},
		"Calling-Station-Id":{"type":"string","value":["aa-bb-cc-dd-ee-ff"]},
		"NAS-Port":{"type":"integer","value":[12]},
		"TLS-Client-Cert-Serial":{"type":"string","value":["01:AB"]}}`
	r, err := ParseRESTRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if r.CallingStationID != "aa-bb-cc-dd-ee-ff" || r.NASIPAddress != "192.0.2.7" || r.CertSerialHex != "01:AB" || r.UserName != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("parsed %+v", r)
	}
	// Alternative shapes.
	r, err = ParseRESTRequest([]byte(`{"Calling-Station-Id":"11-22-33-44-55-66","User-Name":{"value":"x"}}`))
	if err != nil || r.CallingStationID != "11-22-33-44-55-66" || r.UserName != "x" {
		t.Fatalf("lenient shapes: %+v %v", r, err)
	}
}

func TestParseRESTRequest_RefusesBadInput(t *testing.T) {
	for name, body := range map[string]string{
		"not json":      `nope`,
		"array":         `[1]`,
		"conflict":      `{"Calling-Station-Id":{"value":["aa-bb-cc-dd-ee-ff","11-22-33-44-55-66"]}}`,
		"too long":      `{"User-Name":{"value":["` + string(make([]byte, 0)) + longString(300) + `"]}}`,
		"bad value":     `{"User-Name":{"value":[{"x":1}]}}`,
		"empty attr":    `{"User-Name":""}`,
		"null attr":     `{"User-Name":null}`,
		"empty body":    ``,
		"nested object": `{"User-Name":{"value":{"a":1}}}`,
	} {
		r, err := ParseRESTRequest([]byte(body))
		if name == "empty attr" {
			if err != nil || r.UserName != "" {
				t.Errorf("%s: want empty ok, got %+v %v", name, r, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: want error, got %+v", name, r)
		}
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func TestCertSerialDecimal(t *testing.T) {
	cases := map[string]string{"01": "1", "ff": "255", "0xFF": "255", "01:AB": "427", "  1a ": "26",
		"0123456789abcdef0123456789abcdef": "1512366075204170929049582354406559215"}
	for in, want := range cases {
		got, err := CertSerialDecimal(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "zz", "0", "-1", "0x", longString(100)} {
		if _, err := CertSerialDecimal(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	notHex := longString(63) + "g"
	if _, err := NormalizeFingerprint(notHex); err == nil {
		t.Fatal("non-hex must fail")
	}
	good := "AB" + string(make([]byte, 0)) + "cd" + "0123456789012345678901234567890123456789012345678901234567890123"[:60]
	if got, err := NormalizeFingerprint(good); err != nil || got != "abcd"+good[4:] {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := NormalizeFingerprint("abcd"); err == nil {
		t.Fatal("short must fail")
	}
}

// ---- decision mapping ------------------------------------------------------------------

func TestDecide_Table(t *testing.T) {
	full := Settings{CompliantVLAN: "10", QuarantineVLAN: "666", RemediationVLAN: "20", GuestVLAN: "30"}
	cases := []struct {
		name   string
		s      Settings
		st     types.PostureState
		accept bool
		vlan   string
	}{
		{"compliant+vlan", full, types.PostureCompliant, true, "10"},
		{"compliant no vlan", Settings{}, types.PostureCompliant, true, ""},
		{"quarantine vlan", full, types.PostureQuarantined, true, "666"},
		{"quarantine no vlan", Settings{}, types.PostureQuarantined, false, ""},
		{"noncompliant vlan", full, types.PostureNoncompliant, true, "20"},
		{"noncompliant no vlan", Settings{}, types.PostureNoncompliant, false, ""},
		{"unknown, guest configured but not enabled", full, types.PostureUnknown, false, ""},
		{"unknown, guest enabled", Settings{GuestVLAN: "30", GuestEnabled: true}, types.PostureUnknown, true, "30"},
		{"unknown, guest enabled without a valid vlan", Settings{GuestEnabled: true}, types.PostureUnknown, false, ""},
		{"garbage state", Settings{CompliantVLAN: "10"}, types.PostureState("PWNED"), false, ""},
	}
	for _, c := range cases {
		v := Decide(c.s, c.st)
		if v.Accept != c.accept || v.VLAN != c.vlan {
			t.Errorf("%s: got %+v", c.name, v)
		}
	}
	if Reject("x").Accept {
		t.Fatal("Reject must not accept")
	}
}

func TestValidVLAN(t *testing.T) {
	for _, ok := range []string{"1", "10", "4094"} {
		if !ValidVLAN(ok) {
			t.Errorf("%s should be valid", ok)
		}
	}
	for _, bad := range []string{"", "0", "4095", "01", "-1", "1a", "10000", " 1", "1;"} {
		if ValidVLAN(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestReplyAttrs_AlwaysCarriesMarker(t *testing.T) {
	m := ReplyAttrs("")
	if m["control:Tmp-String-0"] != AcceptMarker || len(m) != 1 {
		t.Fatalf("no-vlan reply: %v", m)
	}
	m = ReplyAttrs("42")
	if m["reply:Tunnel-Private-Group-Id:0"] != "42" || m["reply:Tunnel-Type:0"] != "VLAN" || m["reply:Tunnel-Medium-Type:0"] != "IEEE-802" {
		t.Fatalf("vlan reply: %v", m)
	}
}

func TestCheckNASAddress(t *testing.T) {
	for _, ok := range []string{"192.0.2.1", "10.1.2.3", "2001:db8::1"} {
		if err := CheckNASAddress(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"127.0.0.1", "::1", "169.254.169.254", "224.0.0.1", "0.0.0.0", "nas.example.com", "", "::ffff:127.0.0.1"} {
		if CheckNASAddress(bad) == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

// ---- sender against a real UDP listener -----------------------------------------------

type fakeNAS struct {
	conn    *net.UDPConn
	secret  []byte
	got     chan *Packet
	reply   func(req *Packet, reqAuth [16]byte) []byte
	badAuth bool
}

func startFakeNAS(t *testing.T, secret string, mode string) (*fakeNAS, int) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeNAS{conn: c, secret: []byte(secret), got: make(chan *Packet, 16)}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if VerifyRequest(buf[:n], f.secret) != nil {
				continue // a real NAS silently drops a bad request
			}
			p, _ := Decode(buf[:n])
			f.got <- p
			var out []byte
			switch mode {
			case "ack":
				out, _ = EncodeResponse(CodeDisconnectACK, p.ID, p.Authenticator, f.secret, nil)
			case "nak503":
				out, _ = EncodeResponse(CodeDisconnectNAK, p.ID, p.Authenticator, f.secret, []Attr{Uint32Attr(AttrErrorCause, 503)})
			case "nak":
				out, _ = EncodeResponse(CodeDisconnectNAK, p.ID, p.Authenticator, f.secret, []Attr{Uint32Attr(AttrErrorCause, 404)})
			case "forged": // wrong secret in the response authenticator
				out, _ = EncodeResponse(CodeDisconnectACK, p.ID, p.Authenticator, []byte("attacker"), nil)
			case "silent":
				continue
			}
			_, _ = c.WriteToUDP(out, from)
		}
	}()
	return f, c.LocalAddr().(*net.UDPAddr).Port
}

func testSender(attempts int) *Sender {
	return NewSender(UnsafeAllowLoopbackForTests(), WithTiming(300*time.Millisecond, attempts))
}

func TestSendDisconnect_AckNakAndFailures(t *testing.T) {
	attrs := []Attr{StringAttr(AttrUserName, "u"), StringAttr(AttrCallingStationID, "aa-bb-cc-dd-ee-ff")}
	cases := []struct {
		mode    string
		outcome string
		cause   int
	}{
		{"ack", OutcomeACK, 0},
		{"nak503", OutcomeACK, 503}, // session already gone is the wanted end state
		{"nak", OutcomeNAK, 404},
		{"forged", OutcomeFailed, 0}, // a response with a bad authenticator must be ignored
		{"silent", OutcomeFailed, 0},
	}
	for _, c := range cases {
		nas, port := startFakeNAS(t, "shared-secret", c.mode)
		res := testSender(2).SendDisconnect(context.Background(), "127.0.0.1", port, []byte("shared-secret"), attrs)
		if res.Outcome != c.outcome || res.ErrorCause != c.cause {
			t.Errorf("%s: got %+v", c.mode, res)
		}
		select {
		case p := <-nas.got:
			if v, _ := p.Get(AttrCallingStationID); string(v) != "aa-bb-cc-dd-ee-ff" {
				t.Errorf("%s: NAS saw %q", c.mode, v)
			}
			if _, ok := p.Get(AttrEventTimestamp); !ok {
				t.Errorf("%s: missing Event-Timestamp", c.mode)
			}
			if _, ok := p.Get(AttrMessageAuthenticator); !ok {
				t.Errorf("%s: missing Message-Authenticator", c.mode)
			}
		case <-time.After(time.Second):
			t.Errorf("%s: NAS never received a valid request", c.mode)
		}
	}
}

func TestSendDisconnect_WrongSecretIsNeverAcknowledged(t *testing.T) {
	_, port := startFakeNAS(t, "right-secret", "ack")
	res := testSender(1).SendDisconnect(context.Background(), "127.0.0.1", port, []byte("wrong-secret"), nil)
	if res.Outcome != OutcomeFailed {
		t.Fatalf("got %+v", res)
	}
}

func TestSendDisconnect_RetransmitsSamePacket(t *testing.T) {
	nas, port := startFakeNAS(t, "shared-secret", "silent")
	res := testSender(3).SendDisconnect(context.Background(), "127.0.0.1", port, []byte("shared-secret"), nil)
	if res.Outcome != OutcomeFailed || res.Attempts != 3 {
		t.Fatalf("got %+v", res)
	}
	if len(nas.got) != 3 {
		t.Fatalf("NAS saw %d packets, want 3 (bounded retries)", len(nas.got))
	}
	a, b := <-nas.got, <-nas.got
	if a.Authenticator != b.Authenticator || a.ID != b.ID {
		t.Fatal("retransmissions must be identical packets")
	}
}

func TestSendDisconnect_RefusesForbiddenAddressesWithProductionPolicy(t *testing.T) {
	_, port := startFakeNAS(t, "shared-secret", "ack")
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "0.0.0.0", "example.com"} {
		res := NewSender(WithTiming(200*time.Millisecond, 1)).SendDisconnect(context.Background(), host, port, []byte("shared-secret"), nil)
		if res.Outcome != OutcomeFailed {
			t.Errorf("%s: got %+v", host, res)
		}
	}
}
