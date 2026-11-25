// Command eaptls_helper plays the endpoint's part of the device-certificate flow for
// scripts/test_radius.sh: it enrolls a device against a real spire-server, then requests a
// network certificate through the real POST /api/v1/desktop/cert/issue endpoint, presenting
// the device's agent certificate in the TLS handshake. It writes the same files spired keeps
// (device.key, device.crt, token, network.key, network.crt, device-ca.crt).
//
// It is test tooling, not part of the product. The agent's own request code is covered by
// the unit tests in cmd/spired/network_cert_test.go.
//
//	eaptls_helper enroll -server URL -tls-ca FILE -hw UUID -dir DIR   (exit 3 = pending approval)
//	eaptls_helper issue  -server URL -tls-ca FILE -dir DIR -purpose network
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "eaptls_helper: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: eaptls_helper enroll|issue [flags]")
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	server := fs.String("server", "", "server URL (https)")
	tlsCA := fs.String("tls-ca", "", "PEM file that signed the server's TLS certificate")
	hw := fs.String("hw", "", "hardware UUID (enroll)")
	dir := fs.String("dir", "", "directory for the device files")
	purpose := fs.String("purpose", "network", "certificate purpose (issue)")
	_ = fs.Parse(os.Args[2:])
	if *server == "" || *dir == "" || *tlsCA == "" {
		fail("-server, -tls-ca and -dir are required")
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		fail("%v", err)
	}
	switch cmd {
	case "enroll":
		if *hw == "" {
			fail("-hw is required")
		}
		enroll(*server, *tlsCA, *hw, *dir)
	case "issue":
		issue(*server, *tlsCA, *dir, types.CertPurpose(*purpose))
	default:
		fail("unknown command %q", cmd)
	}
}

func httpClient(tlsCA string, clientCert *tls.Certificate) *http.Client {
	pem, err := os.ReadFile(tlsCA)
	if err != nil {
		fail("%v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fail("no certificate in %s", tlsCA)
	}
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

func newKey(path string) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fail("%v", err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		fail("%v", err)
	}
	return k
}

func csrPEM(k *ecdsa.PrivateKey, cn string) string {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		fail("%v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func post(c *http.Client, url, bearer string, in, out any) int {
	body, _ := json.Marshal(in)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		fail("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK && out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			fail("decode %s: %v", url, err)
		}
	} else if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return resp.StatusCode
}

func enroll(server, tlsCA, hw, dir string) {
	keyPath := filepath.Join(dir, "device.key")
	var key *ecdsa.PrivateKey
	if b, err := os.ReadFile(keyPath); err == nil {
		blk, _ := pem.Decode(b)
		k, perr := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if perr != nil {
			fail("%v", perr)
		}
		key = k.(*ecdsa.PrivateKey)
	} else {
		key = newKey(keyPath)
	}
	enrollKey := "eaptls-helper-enrollment-key-" + hw + "-0123456789"
	var out types.EnrollResponse
	code := post(httpClient(tlsCA, nil), server+"/api/v1/desktop/enroll", "", types.EnrollRequest{
		HardwareUUID: hw, Hostname: hw, EnrollmentKey: enrollKey, CSRPEM: csrPEM(key, hw),
	}, &out)
	if code != http.StatusOK || out.Status != types.StatusApproved || out.Token == "" {
		fmt.Fprintf(os.Stderr, "enroll: not approved yet (HTTP %d, status %q)\n", code, out.Status)
		os.Exit(3)
	}
	if strings.TrimSpace(out.DeviceCertificatePEM) == "" {
		fail("the server returned no agent certificate (is the device CA configured?)")
	}
	must(os.WriteFile(filepath.Join(dir, "token"), []byte(out.Token+"\n"), 0600))
	must(os.WriteFile(filepath.Join(dir, "device.crt"), []byte(strings.TrimSpace(out.DeviceCertificatePEM)+"\n"), 0644))
	fmt.Println("enrolled; agent certificate stored")
}

func issue(server, tlsCA, dir string, purpose types.CertPurpose) {
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "device.crt"), filepath.Join(dir, "device.key"))
	if err != nil {
		fail("agent key pair: %v", err)
	}
	tok, err := os.ReadFile(filepath.Join(dir, "token"))
	if err != nil {
		fail("%v", err)
	}
	prefix := string(purpose)
	keyPath := filepath.Join(dir, prefix+".key")
	key := newKey(keyPath)
	var out types.DeviceCertIssueResponse
	code := post(httpClient(tlsCA, &pair), server+"/api/v1/desktop/cert/issue", strings.TrimSpace(string(tok)),
		types.DeviceCertIssueRequest{Purpose: purpose, CSRPEM: csrPEM(key, "helper")}, &out)
	if code != http.StatusOK {
		_ = os.Remove(keyPath)
		os.Exit(4)
	}
	must(os.WriteFile(filepath.Join(dir, prefix+".crt"), []byte(strings.TrimSpace(out.DeviceCertificatePEM)+"\n"), 0644))
	must(os.WriteFile(filepath.Join(dir, "device-ca.crt"), []byte(strings.TrimSpace(out.DeviceCACertPEM)+"\n"), 0644))
	fmt.Printf("issued %s certificate serial=%s not_after=%s\n", purpose, out.Serial, out.NotAfter)
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}
