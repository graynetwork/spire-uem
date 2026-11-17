package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// deviceCertPaths holds the on-disk locations of the device's private key and issued leaf,
// derived from the token path so they share the token directory's 0700 protection.
type deviceCertPaths struct {
	keyPath  string
	certPath string
}

func deviceCertFiles(tokenPath string) deviceCertPaths {
	dir := filepath.Dir(tokenPath)
	return deviceCertPaths{
		keyPath:  filepath.Join(dir, "device.key"),
		certPath: filepath.Join(dir, "device.crt"),
	}
}

// loadOrCreateDeviceKey returns the agent's ECDSA P-256 private key, generating and storing a
// new one (mode 0600) on first use. The private key NEVER leaves the endpoint.
func loadOrCreateDeviceKey(keyPath string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(b)
		if block != nil {
			if k, perr := x509.ParsePKCS8PrivateKey(block.Bytes); perr == nil {
				if ecKey, ok := k.(*ecdsa.PrivateKey); ok && ecKey.Curve == elliptic.P256() {
					return ecKey, nil
				}
			}
			if ecKey, perr := x509.ParseECPrivateKey(block.Bytes); perr == nil && ecKey.Curve == elliptic.P256() {
				return ecKey, nil
			}
		}
		// A corrupt/foreign key is replaced below rather than wedging the agent forever.
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device P-256 key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal device key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := atomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("write device key: %w", err)
	}
	return key, nil
}

// buildDeviceCSR returns a PEM-encoded PKCS#10 CSR for the given key. The server ignores the
// subject, so it is cosmetic.
func buildDeviceCSR(key *ecdsa.PrivateKey, hwUUID string) (string, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hwUUID},
	}
	der, err := x509.CreateCertificateRequest(cryptorand.Reader, tmpl, key)
	if err != nil {
		return "", fmt.Errorf("create device CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// storeDeviceCert atomically writes the issued leaf PEM (mode 0644) next to the key.
func storeDeviceCert(certPath, certPEM string) error {
	return atomicWriteFile(certPath, []byte(strings.TrimSpace(certPEM)+"\n"), 0644)
}

// loadDeviceKeyPair loads the persisted key+cert as a tls.Certificate, or returns ok=false
// when either file is missing or unparsable.
func loadDeviceKeyPair(p deviceCertPaths) (tls.Certificate, bool) {
	certPEM, cerr := os.ReadFile(p.certPath)
	keyPEM, kerr := os.ReadFile(p.keyPath)
	if cerr != nil || kerr != nil {
		return tls.Certificate{}, false
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, false
	}
	return pair, true
}

// deviceCertWindow returns the NotBefore/NotAfter of the persisted leaf, or zero times if
// absent/unparsable.
func deviceCertWindow(p deviceCertPaths) (time.Time, time.Time) {
	certPEM, err := os.ReadFile(p.certPath)
	if err != nil {
		return time.Time{}, time.Time{}
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, time.Time{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}
	}
	return cert.NotBefore, cert.NotAfter
}

// renewalDue reports whether a certificate with the given validity window should be renewed
// now: the agent renews once it has passed ~2/3 of the lifetime. A zero notAfter (no cert)
// is not "due" — there is nothing to renew.
func renewalDue(notBefore, notAfter, now time.Time) bool {
	if notAfter.IsZero() {
		return false
	}
	life := notAfter.Sub(notBefore)
	if life <= 0 {
		return true
	}
	threshold := notBefore.Add(life * 2 / 3)
	return !now.Before(threshold)
}

// atomicWriteFile writes data to path via a temp file + rename, creating the directory 0700.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// buildHTTPClient builds the agent HTTP client. It presents the device key pair for mTLS when
// one is present, and pins the control-plane's TLS trust to serverCAFile / serverCASHA256
// when configured (replacing the system root store for the server connection).
func buildHTTPClient(timeout time.Duration, certPaths deviceCertPaths, serverCAFile, serverCASHA256 string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	// Present the device certificate for mutual TLS when the agent holds one.
	// GetClientCertificate re-reads the pair on every handshake, so a freshly renewed cert is
	// used without a restart.
	tlsCfg.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		pair, ok := loadDeviceKeyPair(certPaths)
		if !ok {
			// No cert yet (pre-claim) — present nothing; optional mode on the server allows it.
			return &tls.Certificate{}, nil
		}
		// Never present a leaf the server would reject in the handshake (expired, not yet
		// valid, or not issued by a CA the server asks for). The server's verifier fails the
		// whole TLS connection for such a cert, which would cut the agent off from check-in
		// and from obtaining a replacement; presenting nothing keeps those paths open.
		if !clientCertUsable(&pair, info, time.Now()) {
			return &tls.Certificate{}, nil
		}
		return &pair, nil
	}

	serverCAFile = strings.TrimSpace(serverCAFile)
	if serverCAFile != "" {
		caPEM, err := os.ReadFile(serverCAFile)
		if err != nil {
			return nil, fmt.Errorf("read server_ca_file %s: %w", serverCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("server_ca_file %s contains no usable certificates", serverCAFile)
		}
		tlsCfg.RootCAs = pool
	}

	serverCASHA256 = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(serverCASHA256, ":", "")))
	if serverCASHA256 != "" {
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server presented no certificate to pin")
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) != serverCASHA256 {
				return fmt.Errorf("server leaf certificate SHA-256 does not match the pinned server_ca_sha256")
			}
			return nil
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// clientCertUsable reports whether pair should be presented in a handshake: its leaf must be
// inside its validity window and, when the server names acceptable CAs, issued by one of them.
func clientCertUsable(pair *tls.Certificate, info *tls.CertificateRequestInfo, now time.Time) bool {
	if pair == nil || len(pair.Certificate) == 0 {
		return false
	}
	leaf := pair.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return false
		}
		leaf = parsed
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	if info != nil && len(info.AcceptableCAs) > 0 && info.SupportsCertificate(pair) != nil {
		return false
	}
	return true
}

// needsCertificate reports whether the agent should request a certificate now: it holds none,
// its leaf is expired or unparsable, or it has passed ~2/3 of its lifetime.
func needsCertificate(notBefore, notAfter, now time.Time) bool {
	if notAfter.IsZero() || !now.Before(notAfter) {
		return true
	}
	return renewalDue(notBefore, notAfter, now)
}

// certRenewCheckInterval is how often the renewal loop re-evaluates the certificate window.
const certRenewCheckInterval = 1 * time.Hour

// runCertRenewalLoop periodically renews the device certificate once it has passed ~2/3 of
// its lifetime. It writes the new key+cert atomically and keeps the old pair until the new
// one is stored, so a failed renewal never leaves the device without a usable certificate.
func runCertRenewalLoop(ctx context.Context, client *http.Client, serverURL, tokenPath, hwUUID string, deviceKey *ecdsa.PrivateKey, certPaths deviceCertPaths) {
	// Jitter the first check a little so a fleet restarted together does not renew in lockstep.
	backoff := 0
	timer := time.NewTimer(time.Duration(1+mathrand.Intn(60)) * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		next := certRenewCheckInterval
		notBefore, notAfter := deviceCertWindow(certPaths)
		if readToken(tokenPath) != "" && needsCertificate(notBefore, notAfter, time.Now()) {
			if err := renewDeviceCert(ctx, client, serverURL, tokenPath, hwUUID, certPaths); err != nil {
				backoff++
				if backoff > 6 {
					backoff = 6
				}
				next = time.Duration(1<<(backoff-1)) * time.Minute
				if next > 30*time.Minute {
					next = 30 * time.Minute
				}
				log.Printf("[spired] certificate renewal failed: %v (retrying in %s)", err, next)
			} else {
				backoff = 0
				log.Printf("[spired] device certificate renewed")
			}
		}
		timer.Reset(next)
	}
}

// renewDeviceCert generates a FRESH key, requests a new leaf for it over the authenticated
// (and mutually authenticated) channel, and only on success swaps in the new key+cert. It
// writes the new key to a side path first, stores the returned cert, then atomically replaces
// the live key — so the current pair keeps working until the new cert is persisted.
func renewDeviceCert(ctx context.Context, client *http.Client, serverURL, tokenPath, hwUUID string, certPaths deviceCertPaths) error {
	token := readToken(tokenPath)
	if token == "" {
		return fmt.Errorf("no token; cannot renew")
	}
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return fmt.Errorf("generate renewal key: %w", err)
	}
	csrPEM, err := buildDeviceCSR(newKey, hwUUID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(types.DeviceCertRenewRequest{CSRPEM: csrPEM})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/cert/renew", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("renew endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var renewResp types.DeviceCertRenewResponse
	if err := json.Unmarshal(respBody, &renewResp); err != nil {
		return fmt.Errorf("decode renew response: %w", err)
	}
	certPEM := strings.TrimSpace(renewResp.DeviceCertificatePEM)
	if certPEM == "" {
		return fmt.Errorf("renew response carried no certificate")
	}

	// Persist the new key to a temp path, then the cert, then atomically swap the live key in.
	newKeyDER, err := x509.MarshalPKCS8PrivateKey(newKey)
	if err != nil {
		return fmt.Errorf("marshal renewal key: %w", err)
	}
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: newKeyDER})
	stagedKey := certPaths.keyPath + ".new"
	if err := atomicWriteFile(stagedKey, newKeyPEM, 0600); err != nil {
		return fmt.Errorf("stage renewal key: %w", err)
	}
	// Store the new cert first (the old key+cert still match and keep working until now).
	if err := storeDeviceCert(certPaths.certPath, certPEM); err != nil {
		_ = os.Remove(stagedKey)
		return fmt.Errorf("store renewed cert: %w", err)
	}
	// Swap the staged key into the live path atomically.
	if err := os.Rename(stagedKey, certPaths.keyPath); err != nil {
		_ = os.Remove(stagedKey)
		return fmt.Errorf("activate renewal key: %w", err)
	}
	return nil
}
