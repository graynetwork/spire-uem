package crypto

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrNoTPMRoots means no TPM manufacturer CA certificates are configured, so an EK
// certificate cannot be anchored and must not be trusted.
var ErrNoTPMRoots = errors.New("no TPM manufacturer CA certificates configured (set SPIRE_TPM_EK_ROOTS to a PEM bundle)")

var (
	tpmTrustMu         sync.RWMutex
	tpmRoots           = x509.NewCertPool()
	tpmIntermediates   = x509.NewCertPool()
	tpmRootsConfigured bool
)

// oidSubjectAltName: TCG EK certificates carry the TPM manufacturer/model/version as a
// critical directoryName SAN that Go's verifier does not understand.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// LoadTPMTrustBundle loads TPM manufacturer CA certificates from a PEM bundle. Self-signed
// certificates become roots; the rest are used as intermediates.
func LoadTPMTrustBundle(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read TPM CA bundle %s: %w", path, err)
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	n := 0
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return 0, fmt.Errorf("parse certificate %d in %s: %w", n+1, path, err)
		}
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil {
			roots.AddCert(cert)
		} else {
			inter.AddCert(cert)
		}
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("no certificates found in %s", path)
	}
	tpmTrustMu.Lock()
	tpmRoots, tpmIntermediates, tpmRootsConfigured = roots, inter, true
	tpmTrustMu.Unlock()
	return n, nil
}

// VerifyEKCertificate validates a TPM 2.0 Endorsement Key (EK) X.509 certificate: it must
// chain to a configured TPM manufacturer CA, be within its validity window, and carry
// exactly the claimed EK public key. Without configured CAs it fails with ErrNoTPMRoots.
func VerifyEKCertificate(certBytes []byte, claimedEKPubPEM string) (*x509.Certificate, error) {
	if len(certBytes) == 0 {
		return nil, errors.New("empty EK certificate")
	}

	// Support either PEM or raw DER encoded certificates
	der := certBytes
	if strings.Contains(string(certBytes), "-----BEGIN CERTIFICATE-----") {
		block, _ := pem.Decode(certBytes)
		if block == nil {
			return nil, errors.New("failed to decode PEM block for EK certificate")
		}
		der = block.Bytes
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse EK certificate: %w", err)
	}

	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("EK certificate is expired or not yet valid (valid: %s to %s)",
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}

	claimedPub, err := ParseRSAPublicKeyPEM(claimedEKPubPEM)
	if err != nil {
		return nil, fmt.Errorf("parse claimed EK public key PEM: %w", err)
	}

	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("EK certificate public key is not RSA")
	}

	if certPub.N.Cmp(claimedPub.N) != 0 || certPub.E != claimedPub.E {
		return nil, errors.New("EK certificate public key does not match claimed EK public key")
	}

	tpmTrustMu.RLock()
	roots, inter, configured := tpmRoots, tpmIntermediates, tpmRootsConfigured
	tpmTrustMu.RUnlock()
	if !configured {
		return cert, ErrNoTPMRoots
	}

	// Tolerate only the TCG SAN as an unhandled critical extension; anything else stays fatal.
	var unhandled []asn1.ObjectIdentifier
	for _, oid := range cert.UnhandledCriticalExtensions {
		if !oid.Equal(oidSubjectAltName) {
			unhandled = append(unhandled, oid)
		}
	}
	cert.UnhandledCriticalExtensions = unhandled

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return cert, fmt.Errorf("EK certificate does not chain to a trusted TPM manufacturer CA: %w", err)
	}
	return cert, nil
}
