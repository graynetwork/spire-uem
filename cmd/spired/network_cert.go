package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

// The network certificate is the key NetworkManager presents for EAP-TLS (802.1X, Wi-Fi). It
// is separate from the agent's mTLS key: its own ECDSA P-256 key, generated here and never
// sent anywhere (the server sees only a CSR), stored root-only beside the agent key as
// network.key, network.crt and device-ca.crt.

// networkCertFilePaths wraps the engine's path set with the helpers the agent needs.
type networkCertFilePaths struct{ engine.NetworkCertPaths }

func networkCertFiles(tokenPath string) networkCertFilePaths {
	return networkCertFilePaths{engine.NetworkCertFilesIn(filepath.Dir(tokenPath))}
}

// all lists every file the network certificate owns, including a staged renewal.
func (p networkCertFilePaths) all() []string {
	return []string{p.Key, p.Cert, p.CA, p.Key + ".new", p.Cert + ".new"}
}

// networkCertNeeded reports whether any assigned NETWORK_PROFILE asks for the device
// certificate (client_cert_source "device").
func networkCertNeeded(policies []types.AssignedPolicy) bool {
	for _, pol := range policies {
		if pol.PolicyType != types.PolicyTypeNetworkProfile {
			continue
		}
		var p types.NetworkProfilePayload
		if err := json.Unmarshal(pol.Payload, &p); err != nil {
			continue
		}
		if engine.PayloadUsesDeviceNetworkCert(p) {
			return true
		}
	}
	return false
}

// networkCertManager keeps the network key and certificate in step with the assigned
// policies: it requests them while a profile needs them, renews them at ~2/3 of their
// lifetime with a fresh key, and deletes them once no profile needs them.
type networkCertManager struct {
	client    *http.Client
	serverURL string
	tokenPath string
	hwUUID    string
	paths     networkCertFilePaths
	now       func() time.Time
	// onIssued runs after a certificate was stored (spired uses it to trigger a check-in so
	// the profile is applied without waiting for the next poll).
	onIssued func()

	mu      sync.Mutex
	known   bool // a check-in has told us whether a profile needs the certificate
	needed  bool
	wake    chan struct{}
	backoff int
}

func newNetworkCertManager(client *http.Client, serverURL, tokenPath, hwUUID string, onIssued func()) *networkCertManager {
	return &networkCertManager{
		client: client, serverURL: serverURL, tokenPath: tokenPath, hwUUID: hwUUID,
		paths: networkCertFiles(tokenPath), now: time.Now, onIssued: onIssued,
		wake: make(chan struct{}, 1),
	}
}

// setNeeded records, from a completed check-in, whether any assigned profile uses the device
// certificate. Until the first call the manager never deletes anything: after a restart it
// does not yet know what is assigned.
func (m *networkCertManager) setNeeded(needed bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.known, m.needed = true, needed
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *networkCertManager) state() (known, needed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.known, m.needed
}

// loadNetworkPair returns the stored leaf when key and certificate parse and match.
func (m *networkCertManager) loadNetworkPair() (*x509.Certificate, bool) {
	certPEM, cerr := os.ReadFile(m.paths.Cert)
	keyPEM, kerr := os.ReadFile(m.paths.Key)
	if cerr != nil || kerr != nil {
		return nil, false
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}
	return leaf, true
}

// remove deletes the network key, certificate, CA copy and any staged renewal.
func (m *networkCertManager) remove() error {
	var firstErr error
	removed := false
	for _, p := range m.paths.all() {
		if err := os.Remove(p); err == nil {
			removed = true
		} else if !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	if removed {
		log.Printf("[spired] network certificate removed (no assigned profile uses it)")
	}
	return firstErr
}

// reconcile does one pass. It returns an error only when issuance failed (the caller backs
// off); the current key and certificate stay exactly as they were in that case.
func (m *networkCertManager) reconcile(ctx context.Context) error {
	known, needed := m.state()
	if !known {
		return nil
	}
	if !needed {
		return m.remove()
	}
	if readToken(m.tokenPath) == "" {
		return nil
	}
	if leaf, ok := m.loadNetworkPair(); ok && !needsCertificate(leaf.NotBefore, leaf.NotAfter, m.now()) {
		return nil
	}
	if err := m.issue(ctx); err != nil {
		return err
	}
	log.Printf("[spired] network certificate issued")
	if m.onIssued != nil {
		m.onIssued()
	}
	return nil
}

// run reconciles when woken by a check-in and at least every certRenewCheckInterval, backing
// off after failures.
func (m *networkCertManager) run(ctx context.Context) {
	for {
		next := certRenewCheckInterval
		if err := m.reconcile(ctx); err != nil {
			m.backoff++
			if m.backoff > 6 {
				m.backoff = 6
			}
			next = time.Duration(1<<(m.backoff-1)) * time.Minute
			if next > 30*time.Minute {
				next = 30 * time.Minute
			}
			log.Printf("[spired] network certificate issuance failed: %v (retrying in %s)", err, next)
		} else {
			m.backoff = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-time.After(next):
		}
	}
}

// issue generates a FRESH key, requests a certificate for it and, only on success, swaps the
// new key and certificate in. Both are staged and checked to match before either replaces
// the live file, so a failed attempt never changes the current pair.
func (m *networkCertManager) issue(ctx context.Context) error {
	token := readToken(m.tokenPath)
	if token == "" {
		return fmt.Errorf("no token; cannot request a network certificate")
	}
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return fmt.Errorf("generate network key: %w", err)
	}
	csrPEM, err := buildDeviceCSR(newKey, m.hwUUID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(types.DeviceCertIssueRequest{Purpose: types.CertPurposeNetwork, CSRPEM: csrPEM})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.serverURL+"/api/v1/desktop/cert/issue", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("issue endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out types.DeviceCertIssueResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return fmt.Errorf("decode issue response: %w", err)
	}
	if out.Purpose != types.CertPurposeNetwork {
		return fmt.Errorf("issue response is for purpose %q, not network", out.Purpose)
	}
	certPEM := strings.TrimSpace(out.DeviceCertificatePEM)
	caPEM := strings.TrimSpace(out.DeviceCACertPEM)
	if certPEM == "" || caPEM == "" {
		return fmt.Errorf("issue response lacked the certificate or the device CA")
	}
	if err := m.checkIssued(certPEM, newKey); err != nil {
		return err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(newKey)
	if err != nil {
		return fmt.Errorf("marshal network key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := tls.X509KeyPair([]byte(certPEM+"\n"), keyPEM); err != nil {
		return fmt.Errorf("issued certificate does not match the new key: %w", err)
	}
	stagedKey, stagedCert := m.paths.Key+".new", m.paths.Cert+".new"
	if err := atomicWriteFile(stagedKey, keyPEM, 0600); err != nil {
		return fmt.Errorf("stage network key: %w", err)
	}
	if err := atomicWriteFile(stagedCert, []byte(certPEM+"\n"), 0644); err != nil {
		_ = os.Remove(stagedKey)
		return fmt.Errorf("stage network certificate: %w", err)
	}
	if err := atomicWriteFile(m.paths.CA, []byte(caPEM+"\n"), 0644); err != nil {
		_ = os.Remove(stagedKey)
		_ = os.Remove(stagedCert)
		return fmt.Errorf("store device CA: %w", err)
	}
	// Swap both in. If the process dies between the two renames the pair does not match;
	// loadNetworkPair then reports it missing and the next pass issues a new one.
	if err := os.Rename(stagedCert, m.paths.Cert); err != nil {
		_ = os.Remove(stagedKey)
		_ = os.Remove(stagedCert)
		return fmt.Errorf("activate network certificate: %w", err)
	}
	if err := os.Rename(stagedKey, m.paths.Key); err != nil {
		_ = os.Remove(stagedKey)
		return fmt.Errorf("activate network key: %w", err)
	}
	return nil
}

// checkIssued refuses a certificate the agent must not install: unparsable, for another key,
// outside its validity window, or naming no device.
func (m *networkCertManager) checkIssued(certPEM string, key *ecdsa.PrivateKey) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("issued certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse issued certificate: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return fmt.Errorf("issued certificate is not for the requested key")
	}
	now := m.now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("issued certificate is outside its validity window")
	}
	if crypto.DeviceIDFromCert(leaf) == "" {
		return fmt.Errorf("issued certificate names no device")
	}
	return nil
}
