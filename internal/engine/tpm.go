package engine

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	defaultTPMDevicePath = "/dev/tpmrm0"
	fallbackTPMPath      = "/dev/tpm0"
)

// AttestationPCRs are the standard boot integrity and Secure Boot PCRs measured during attestation.
var AttestationPCRs = []int{0, 2, 4, 7}

// DetectTPM2Device returns the path to the hardware TPM 2.0 resource manager (/dev/tpmrm0) if present.
func DetectTPM2Device() (string, bool) {
	for _, p := range []string{defaultTPMDevicePath, fallbackTPMPath} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, true
		}
	}
	return "", false
}

// CheckSecureBootState inspects EFI variables (/sys/firmware/efi/efivars/SecureBoot-*) and PCR 7.
func CheckSecureBootState(pcr7Hex string) bool {
	matches, _ := filepath.Glob("/sys/firmware/efi/efivars/SecureBoot-*")
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err == nil && len(data) >= 5 && data[len(data)-1] == 1 {
			return true
		}
	}
	trimmed := strings.Trim(strings.ToLower(strings.TrimSpace(pcr7Hex)), "0")
	return trimmed != ""
}

// PerformTPMAttestation executes the TPM 2.0 challenge-response attestation ceremony against spire-server.
// It uses /dev/tpmrm0 via github.com/google/go-tpm/legacy/tpm2 when hardware TPM 2.0 is available,
// or software-backed TPM simulation when SPIRE_SIMULATE_TPM2=1 is enabled.
// If TPM is absent and simulation is disabled, fails closed and reports FAILED attestation status.
func PerformTPMAttestation(ctx context.Context, client *http.Client, serverURL, token, hwUUID string) (*types.AttestationVerifyResponse, error) {
	tpmPath, hasHardwareTPM := DetectTPM2Device()
	if !hasHardwareTPM && os.Getenv("SPIRE_SIMULATE_TPM2") != "1" {
		// Fail-closed: report FAILED attestation to spire-server
		verifyReqBody, _ := json.Marshal(types.AttestationVerifyRequest{
			HardwareUUID:      hwUUID,
			Nonce:             "absent-tpm",
			SecureBootEnabled: false,
		})
		verifyReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/attest/verify", bytes.NewReader(verifyReqBody))
		if err == nil {
			verifyReq.Header.Set("Content-Type", "application/json")
			verifyReq.Header.Set("Authorization", "Bearer "+token)
			if resp, postErr := client.Do(verifyReq); postErr == nil {
				_ = resp.Body.Close()
			}
		}
		return &types.AttestationVerifyResponse{
			Status:            types.AttestationFailed,
			SecureBootEnabled: false,
			VerifiedAt:        time.Now().UTC(),
		}, nil
	}

	var (
		ekPubPEM    string
		akPubPEM    string
		ekCertPEM   string
		simEKPriv   *rsa.PrivateKey
		simAKPriv   *rsa.PrivateKey
		rwc         io.ReadWriteCloser
		ekHandle    tpmutil.Handle
		akHandle    tpmutil.Handle
		pcrValues   = make(map[string]string)
	)

	if hasHardwareTPM {
		var err error
		rwc, err = tpm2.OpenTPM(tpmPath)
		if err != nil {
			return nil, fmt.Errorf("open TPM %s: %w", tpmPath, err)
		}
		defer rwc.Close()

		// Read NVRAM EK certificate if provisioned by OEM/manufacturer
		for _, h := range []tpmutil.Handle{0x01c00002, 0x01c0000a} {
			if derBytes, err := tpm2.NVReadEx(rwc, h, tpm2.HandleOwner, "", 0); err == nil && len(derBytes) > 0 {
				ekCertPEM = string(pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: derBytes,
				}))
				break
			}
		}

		ekTemplate := tpm2.Public{
			Type:       tpm2.AlgRSA,
			NameAlg:    tpm2.AlgSHA256,
			Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
			RSAParameters: &tpm2.RSAParams{
				Symmetric: &tpm2.SymScheme{
					Alg:     tpm2.AlgAES,
					KeyBits: 128,
					Mode:    tpm2.AlgCFB,
				},
				KeyBits: 2048,
			},
		}
		var ekPub crypto.PublicKey
		ekHandle, ekPub, err = tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", ekTemplate)
		if err != nil {
			return nil, fmt.Errorf("tpm2 CreatePrimary EK: %w", err)
		}
		defer tpm2.FlushContext(rwc, ekHandle)

		ekPubPEM, err = encodePublicKeyPEM(ekPub)
		if err != nil {
			return nil, err
		}

		akTemplate := tpm2.Public{
			Type:       tpm2.AlgRSA,
			NameAlg:    tpm2.AlgSHA256,
			Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagSign,
			RSAParameters: &tpm2.RSAParams{
				Sign: &tpm2.SigScheme{
					Alg:  tpm2.AlgRSASSA,
					Hash: tpm2.AlgSHA256,
				},
				KeyBits: 2048,
			},
		}
		var akPub crypto.PublicKey
		akHandle, akPub, err = tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", akTemplate)
		if err != nil {
			return nil, fmt.Errorf("tpm2 CreatePrimary AK: %w", err)
		}
		defer tpm2.FlushContext(rwc, akHandle)

		akPubPEM, err = encodePublicKeyPEM(akPub)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		simEKPriv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		ekPubPEM, _ = encodePublicKeyPEM(&simEKPriv.PublicKey)
		ekCertPEM = generateSimulatedEKCert(simEKPriv)

		simAKPriv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		akPubPEM, _ = encodePublicKeyPEM(&simAKPriv.PublicKey)
	}

	// Step 1: Request encrypted challenge nonce from POST /api/v1/desktop/attest/challenge
	chalReqBody, _ := json.Marshal(types.AttestationChallengeRequest{
		HardwareUUID:     hwUUID,
		EKPublicPEM:      ekPubPEM,
		AKPublicPEM:      akPubPEM,
		EKCertificatePEM: ekCertPEM,
	})
	chalReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/attest/challenge", bytes.NewReader(chalReqBody))
	if err != nil {
		return nil, err
	}
	chalReq.Header.Set("Content-Type", "application/json")
	chalReq.Header.Set("Authorization", "Bearer "+token)

	chalHTTPResp, err := client.Do(chalReq)
	if err != nil {
		return nil, fmt.Errorf("attestation challenge request: %w", err)
	}
	defer chalHTTPResp.Body.Close()

	if chalHTTPResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(chalHTTPResp.Body)
		return nil, fmt.Errorf("attestation challenge returned HTTP %d: %s", chalHTTPResp.StatusCode, strings.TrimSpace(string(b)))
	}

	var chalResp types.AttestationChallengeResponse
	if err := json.NewDecoder(chalHTTPResp.Body).Decode(&chalResp); err != nil {
		return nil, fmt.Errorf("decode attestation challenge response: %w", err)
	}

	// Step 2: Read PCRs 0, 2, 4, 7 and produce signed quote over challenge nonce
	var (
		decryptedNonce string
		quoteAttest    []byte
		quoteSig       []byte
	)

	if hasHardwareTPM {
		pcrSel := tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: AttestationPCRs,
		}
		pcrMap, err := tpm2.ReadPCRs(rwc, pcrSel)
		if err != nil {
			return nil, fmt.Errorf("tpm2 ReadPCRs: %w", err)
		}
		for pcrIdx, digest := range pcrMap {
			pcrValues[fmt.Sprintf("%d", pcrIdx)] = hex.EncodeToString(digest)
		}

		attestBytes, sig, err := tpm2.Quote(rwc, akHandle, "", "", chalResp.EncryptedNonce, pcrSel, tpm2.AlgNull)
		if err != nil {
			return nil, fmt.Errorf("tpm2 Quote: %w", err)
		}
		quoteAttest = attestBytes
		if sig != nil && sig.RSA != nil {
			quoteSig = sig.RSA.Signature
		}
	} else {
		plainNonceBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, simEKPriv, chalResp.EncryptedNonce, nil)
		if err == nil {
			decryptedNonce = string(plainNonceBytes)
		} else {
			decryptedNonce = string(chalResp.EncryptedNonce)
		}

		for _, idx := range AttestationPCRs {
			sum := sha256.Sum256([]byte(fmt.Sprintf("spire-pcr-%d-%s", idx, hwUUID)))
			pcrValues[fmt.Sprintf("%d", idx)] = hex.EncodeToString(sum[:])
		}

		quotePayload, _ := json.Marshal(map[string]any{
			"nonce":      decryptedNonce,
			"pcr_values": pcrValues,
		})
		quoteAttest = quotePayload
		digest := sha256.Sum256(quoteAttest)
		quoteSig, err = rsa.SignPKCS1v15(rand.Reader, simAKPriv, crypto.SHA256, digest[:])
		if err != nil {
			return nil, fmt.Errorf("sign simulated TPM quote: %w", err)
		}
	}

	secureBoot := CheckSecureBootState(pcrValues["7"])

	// Step 3: Submit signed quote and PCR values to POST /api/v1/desktop/attest/verify
	verifyReqBody, _ := json.Marshal(types.AttestationVerifyRequest{
		HardwareUUID:      hwUUID,
		EKPublicPEM:       ekPubPEM,
		AKPublicPEM:       akPubPEM,
		EKCertificatePEM:  ekCertPEM,
		Nonce:             decryptedNonce,
		PCRValues:         pcrValues,
		QuoteAttest:       quoteAttest,
		QuoteSignature:    quoteSig,
		SecureBootEnabled: secureBoot,
	})
	verifyReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/attest/verify", bytes.NewReader(verifyReqBody))
	if err != nil {
		return nil, err
	}
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("Authorization", "Bearer "+token)

	verifyHTTPResp, err := client.Do(verifyReq)
	if err != nil {
		return nil, fmt.Errorf("attestation verify request: %w", err)
	}
	defer verifyHTTPResp.Body.Close()

	if verifyHTTPResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(verifyHTTPResp.Body)
		return nil, fmt.Errorf("attestation verify returned HTTP %d: %s", verifyHTTPResp.StatusCode, strings.TrimSpace(string(b)))
	}

	var verifyResp types.AttestationVerifyResponse
	if err := json.NewDecoder(verifyHTTPResp.Body).Decode(&verifyResp); err != nil {
		return nil, fmt.Errorf("decode attestation verify response: %w", err)
	}
	return &verifyResp, nil
}

func generateSimulatedEKCert(priv *rsa.PrivateKey) string {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "SpireUEM Simulated TPM 2.0 EK",
			Organization: []string{"SpireUEM"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return ""
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block))
}

func encodePublicKeyPEM(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key PKIX: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}
