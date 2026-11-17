package config

import "testing"

func TestResolveDeviceMTLSMode(t *testing.T) {
	cases := map[string]struct {
		want    string
		wantErr bool
	}{
		"":         {MTLSOptional, false},
		"optional": {MTLSOptional, false},
		"OFF":      {MTLSOff, false},
		"Required": {MTLSRequired, false},
		"  off  ":  {MTLSOff, false},
		"strict":   {"", true},
	}
	for in, exp := range cases {
		got, err := ResolveDeviceMTLSMode(in)
		if exp.wantErr {
			if err == nil {
				t.Errorf("ResolveDeviceMTLSMode(%q) expected error", in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveDeviceMTLSMode(%q) unexpected error: %v", in, err)
		}
		if got != exp.want {
			t.Errorf("ResolveDeviceMTLSMode(%q) = %q, want %q", in, got, exp.want)
		}
	}
}

func TestCheckDeviceMTLSTransport(t *testing.T) {
	// required + trusted proxy must be refused.
	if err := CheckDeviceMTLSTransport(MTLSRequired, TransportProxy, true); err == nil {
		t.Fatal("expected required + trusted proxy to be refused")
	}
	if err := CheckDeviceMTLSTransport(MTLSRequired, TransportBuiltinTLS, true); err == nil {
		t.Fatal("expected required with trustProxy=true to be refused regardless of transport")
	}
	// required + built-in TLS (no proxy) is allowed.
	if err := CheckDeviceMTLSTransport(MTLSRequired, TransportBuiltinTLS, false); err != nil {
		t.Fatalf("required + builtin TLS should be allowed: %v", err)
	}
	// optional/off are never constrained by the proxy.
	if err := CheckDeviceMTLSTransport(MTLSOptional, TransportProxy, true); err != nil {
		t.Fatalf("optional + proxy should be allowed: %v", err)
	}
	if err := CheckDeviceMTLSTransport(MTLSOff, TransportProxy, true); err != nil {
		t.Fatalf("off + proxy should be allowed: %v", err)
	}
}

func TestLoad_DeviceMTLSEnv(t *testing.T) {
	t.Setenv("SPIRE_DEVICE_MTLS", "required")
	t.Setenv("SPIRE_DEVICE_CA_CERT_FILE", "/x/ca.crt")
	t.Setenv("SPIRE_DEVICE_CERT_VALIDITY", "72h")
	t.Setenv("SPIRE_AGENT_SERVER_CA_FILE", "/x/server-ca.pem")
	cfg := Load("")
	if cfg.Server.DeviceMTLSMode != "required" {
		t.Errorf("DeviceMTLSMode = %q, want required", cfg.Server.DeviceMTLSMode)
	}
	if cfg.Server.DeviceCACertFile != "/x/ca.crt" {
		t.Errorf("DeviceCACertFile = %q", cfg.Server.DeviceCACertFile)
	}
	if cfg.Server.DeviceCertValidity.Hours() != 72 {
		t.Errorf("DeviceCertValidity = %v, want 72h", cfg.Server.DeviceCertValidity)
	}
	if cfg.Agent.ServerCAFile != "/x/server-ca.pem" {
		t.Errorf("ServerCAFile = %q", cfg.Agent.ServerCAFile)
	}
}
