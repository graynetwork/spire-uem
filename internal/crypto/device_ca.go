package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DeviceCAURIScheme is the URI SAN scheme the device CA stamps into every issued leaf:
// spire://device/<device-id>. It identifies the device the certificate belongs to without
// trusting any name the agent requested in its CSR.
const DeviceCAURIScheme = "spire"

// DefaultDeviceCertValidity is how long an issued device leaf is valid when the caller does
// not override it. Renewal (see the agent) happens well before this.
const DefaultDeviceCertValidity = 30 * 24 * time.Hour

// IssuedCert is the result of issuing a device leaf certificate.
type IssuedCert struct {
	// CertPEM is the PEM-encoded leaf certificate.
	CertPEM []byte
	// Serial is the certificate serial number as a decimal string.
	Serial string
	// FingerprintSHA256 is the hex-encoded SHA-256 of the DER leaf (lowercase).
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
}

// DeviceCA issues short-lived client-auth leaf certificates for enrolled devices and exposes
// the CA certificate so the server can build a verification pool. The interface keeps the
// issuance surface small so an external CA can replace the built-in one later without
// touching callers.
type DeviceCA interface {
	// IssueFromCSR verifies csrDER (a DER-encoded PKCS#10 CSR), ignores every name and
	// extension it requests, and issues a client-auth-only leaf whose single URI SAN is
	// spire://device/<deviceID>. validity<=0 uses DefaultDeviceCertValidity.
	IssueFromCSR(csrDER []byte, deviceID string, validity time.Duration) (*IssuedCert, error)
	// CACertPEM returns the PEM-encoded CA certificate (for the client-cert verification pool).
	CACertPEM() []byte
	// CertPool returns an *x509.CertPool containing the CA certificate.
	CertPool() *x509.CertPool
}

// FileDeviceCA is a DeviceCA backed by an on-disk ECDSA P-256 key and self-signed CA
// certificate. It generates both on first start if absent (key mode 0600), like the KEK.
type FileDeviceCA struct {
	mu       sync.Mutex
	key      *ecdsa.PrivateKey
	cert     *x509.Certificate
	certPEM  []byte
	pool     *x509.CertPool
	certPath string
	keyPath  string
}

// NewFileDeviceCA loads the CA cert+key from the given paths, or generates a new P-256 CA
// (self-signed, 10-year validity) when either file is missing. The key is written mode 0600.
func NewFileDeviceCA(certPath, keyPath string) (*FileDeviceCA, error) {
	certPath = strings.TrimSpace(certPath)
	keyPath = strings.TrimSpace(keyPath)
	if certPath == "" || keyPath == "" {
		return nil, errors.New("device CA cert and key paths must both be set")
	}
	ca := &FileDeviceCA{certPath: certPath, keyPath: keyPath}

	certData, certErr := os.ReadFile(certPath)
	keyData, keyErr := os.ReadFile(keyPath)

	switch {
	case certErr == nil && keyErr == nil:
		if err := ca.load(certData, keyData); err != nil {
			return nil, err
		}
	case os.IsNotExist(certErr) || os.IsNotExist(keyErr):
		if err := ca.generate(); err != nil {
			return nil, err
		}
	default:
		if certErr != nil {
			return nil, fmt.Errorf("read device CA cert %s: %w", certPath, certErr)
		}
		return nil, fmt.Errorf("read device CA key %s: %w", keyPath, keyErr)
	}
	return ca, nil
}

func (ca *FileDeviceCA) load(certData, keyData []byte) error {
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("decode device CA cert %s: not a CERTIFICATE PEM block", ca.certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse device CA cert %s: %w", ca.certPath, err)
	}
	if !cert.IsCA {
		return fmt.Errorf("device CA cert %s is not a CA certificate", ca.certPath)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return fmt.Errorf("decode device CA key %s: invalid PEM block", ca.keyPath)
	}
	var key *ecdsa.PrivateKey
	if k, perr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); perr == nil {
		if ecKey, ok := k.(*ecdsa.PrivateKey); ok {
			key = ecKey
		}
	}
	if key == nil {
		ecKey, perr := x509.ParseECPrivateKey(keyBlock.Bytes)
		if perr != nil {
			return fmt.Errorf("parse device CA key %s: %w", ca.keyPath, perr)
		}
		key = ecKey
	}
	if key.Curve != elliptic.P256() {
		return fmt.Errorf("device CA key %s is not an ECDSA P-256 key", ca.keyPath)
	}
	ca.key = key
	ca.cert = cert
	ca.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	ca.pool = x509.NewCertPool()
	ca.pool.AddCert(cert)
	return nil
}

func (ca *FileDeviceCA) generate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate device CA P-256 key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "SpireUEM Device CA",
			Organization: []string{"SpireUEM"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create device CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse freshly created device CA certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal device CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	if err := atomicWrite(ca.keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write device CA key: %w", err)
	}
	if err := atomicWrite(ca.certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write device CA cert: %w", err)
	}

	ca.key = key
	ca.cert = cert
	ca.certPEM = certPEM
	ca.pool = x509.NewCertPool()
	ca.pool.AddCert(cert)
	return nil
}

// IssueFromCSR verifies the CSR signature and issues a client-auth leaf. The CSR's requested
// subject, SANs and extensions are deliberately ignored: only the CSR public key is used, and
// the only SAN placed on the leaf is spire://device/<deviceID>.
func (ca *FileDeviceCA) IssueFromCSR(csrDER []byte, deviceID string, validity time.Duration) (*IssuedCert, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return nil, errors.New("device id is required to issue a certificate")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	// Verify the CSR was signed by the private key matching its public key. This is what
	// proves the agent holds the key it is asking us to certify.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}
	// Accept only EC P-256 public keys; reject RSA, Ed25519 and other curves so every leaf
	// has the shape the spec requires.
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("CSR public key must be ECDSA P-256, got %T", csr.PublicKey)
	}
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("CSR public key must be ECDSA on curve P-256")
	}

	if validity <= 0 {
		validity = DefaultDeviceCertValidity
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	spiffeURI := &url.URL{Scheme: DeviceCAURIScheme, Host: "device", Path: "/" + deviceID}
	now := time.Now().UTC()
	leaf := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    now.Add(-2 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Client auth only: a stolen device leaf cannot be used to impersonate a server.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}

	ca.mu.Lock()
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, pub, ca.key)
	ca.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("sign device leaf certificate: %w", err)
	}

	sum := sha256.Sum256(der)
	return &IssuedCert{
		CertPEM:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:            serial.String(),
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
	}, nil
}

// CACertPEM returns the PEM-encoded CA certificate.
func (ca *FileDeviceCA) CACertPEM() []byte {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	out := make([]byte, len(ca.certPEM))
	copy(out, ca.certPEM)
	return out
}

// CertPool returns an x509 pool holding the CA certificate.
func (ca *FileDeviceCA) CertPool() *x509.CertPool {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.pool
}

// DeviceIDFromCert extracts the device id from a leaf's spire://device/<id> URI SAN. It
// returns "" when the certificate carries no such SAN.
func DeviceIDFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, u := range cert.URIs {
		if u == nil {
			continue
		}
		if u.Scheme == DeviceCAURIScheme && strings.EqualFold(u.Host, "device") {
			return strings.TrimPrefix(u.Path, "/")
		}
	}
	return ""
}

// FingerprintSHA256 returns the lowercase hex SHA-256 of a certificate's DER bytes.
func FingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	// Serials must be positive and non-zero.
	return serial.Add(serial, big.NewInt(1)), nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
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
