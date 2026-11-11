package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ManufacturerTPMRoots holds optional manufacturer Root CAs for TPM 2.0 EK verification.
var ManufacturerTPMRoots = x509.NewCertPool()

// VerifyEKCertificate validates a TPM 2.0 Endorsement Key (EK) X.509 certificate
// and ensures its embedded public key exactly matches the claimed EK public key.
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

	// Verify chain if root pool has certs; otherwise log/accept leaf validation
	if !ManufacturerTPMRoots.Equal(x509.NewCertPool()) {
		opts := x509.VerifyOptions{
			Roots: ManufacturerTPMRoots,
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageAny,
			},
		}
		if _, err := cert.Verify(opts); err != nil {
			return cert, fmt.Errorf("EK certificate root CA verification warning: %w", err)
		}
	}

	return cert, nil
}
