package config

import "testing"

func TestResolveServerTransport(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ServerConfig
		proxy   bool
		want    string
		wantErr bool
	}{
		{"plain http on all interfaces is refused", ServerConfig{ListenAddr: ":8080"}, false, "", true},
		{"plain http on a LAN address is refused", ServerConfig{ListenAddr: "10.0.0.5:8080"}, false, "", true},
		{"builtin tls", ServerConfig{ListenAddr: ":8443", TLSCertFile: "c.pem", TLSKeyFile: "k.pem"}, false, TransportBuiltinTLS, false},
		{"cert without key", ServerConfig{ListenAddr: ":8443", TLSCertFile: "c.pem"}, false, "", true},
		{"trusted proxy", ServerConfig{ListenAddr: ":8080"}, true, TransportProxy, false},
		{"loopback ipv4", ServerConfig{ListenAddr: "127.0.0.1:8080"}, false, TransportLoopback, false},
		{"loopback ipv6", ServerConfig{ListenAddr: "[::1]:8080"}, false, TransportLoopback, false},
		{"explicit opt-in", ServerConfig{ListenAddr: ":8080", AllowInsecureHTTP: true}, false, TransportInsecure, false},
	}
	for _, c := range cases {
		got, err := ResolveServerTransport(c.cfg, c.proxy)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%s: got (%q, %v), want %q err=%v", c.name, got, err, c.want, c.wantErr)
		}
	}
}

func TestCheckAgentServerURL(t *testing.T) {
	ok := []struct {
		url   string
		allow bool
	}{
		{"https://uem.example.com", false},
		{"http://localhost:8080", false},
		{"http://127.0.0.1:8080", false},
		{"http://spire-server:8080", true},
	}
	for _, c := range ok {
		if err := CheckAgentServerURL(c.url, c.allow); err != nil {
			t.Errorf("%s allow=%v: %v", c.url, c.allow, err)
		}
	}
	for _, u := range []string{"http://uem.example.com", "ftp://x", "not a url", ""} {
		if err := CheckAgentServerURL(u, false); err == nil {
			t.Errorf("%q: expected refusal", u)
		}
	}
}
