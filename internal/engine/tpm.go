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
	"errors"
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
		akPublicTPM []byte
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

		ekHandle, akHandle, ekPubPEM, akPubPEM, akPublicTPM, err = createAttestationKeys(rwc)
		if err != nil {
			return nil, err
		}
		defer tpm2.FlushContext(rwc, ekHandle)
		defer tpm2.FlushContext(rwc, akHandle)
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
		AKPublicTPM:      akPublicTPM,
		Simulated:        !hasHardwareTPM,
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
		secret, attestBytes, sig, pcrs, err := activateAndQuote(rwc, ekHandle, akHandle, chalResp.CredentialBlob, chalResp.EncryptedSecret)
		if err != nil {
			return nil, err
		}
		decryptedNonce = hex.EncodeToString(secret)
		quoteAttest, quoteSig = attestBytes, sig
		for k, v := range pcrs {
			pcrValues[k] = v
		}
	} else {
		plainNonceBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, simEKPriv, chalResp.EncryptedNonce, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt simulated TPM challenge: %w", err)
		}
		decryptedNonce = string(plainNonceBytes)

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
		Simulated:         !hasHardwareTPM,
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

// tcgEKAuthPolicy is the TCG default EK policy digest: PolicySecret(TPM_RH_ENDORSEMENT).
var tcgEKAuthPolicy = []byte{
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
	0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
}

// tcgEKTemplateRSA is the TCG EK Credential Profile default RSA-2048 EK template (L-1).
// Using it exactly yields the same EK the manufacturer certified in NV, so the EK
// certificate's public key matches the key we present.
func tcgEKTemplateRSA() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: tcgEKAuthPolicy,
		RSAParameters: &tpm2.RSAParams{
			Symmetric:  &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
}

// akTemplateRSA is a restricted RSASSA-SHA256 signing key usable for TPM2_Quote.
func akTemplateRSA() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagSign | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Sign:    &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256},
			KeyBits: 2048,
		},
	}
}

// createAttestationKeys creates the EK (TCG default template) and an AK, returning their
// handles, PEM public keys and the AK's TPMT_PUBLIC area for the server's credential challenge.
func createAttestationKeys(rw io.ReadWriter) (ekHandle, akHandle tpmutil.Handle, ekPEM, akPEM string, akPublicTPM []byte, err error) {
	ekHandle, ekPub, err := tpm2.CreatePrimary(rw, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", tcgEKTemplateRSA())
	if err != nil {
		return 0, 0, "", "", nil, fmt.Errorf("tpm2 CreatePrimary EK: %w", err)
	}
	if ekPEM, err = encodePublicKeyPEM(ekPub); err != nil {
		tpm2.FlushContext(rw, ekHandle)
		return 0, 0, "", "", nil, err
	}

	akHandle, akPublicTPM, _, _, _, _, err = tpm2.CreatePrimaryEx(rw, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", akTemplateRSA())
	if err != nil {
		tpm2.FlushContext(rw, ekHandle)
		return 0, 0, "", "", nil, fmt.Errorf("tpm2 CreatePrimary AK: %w", err)
	}
	akPub, err := tpm2.DecodePublic(akPublicTPM)
	if err == nil {
		var key crypto.PublicKey
		if key, err = akPub.Key(); err == nil {
			akPEM, err = encodePublicKeyPEM(key)
		}
	}
	if err != nil {
		tpm2.FlushContext(rw, ekHandle)
		tpm2.FlushContext(rw, akHandle)
		return 0, 0, "", "", nil, fmt.Errorf("decode AK public area: %w", err)
	}
	return ekHandle, akHandle, ekPEM, akPEM, akPublicTPM, nil
}

// activateAndQuote recovers the server's credential secret with TPM2_ActivateCredential
// (which succeeds only if the AK and EK live in this TPM) and quotes the attestation PCRs
// with that secret as extraData, binding the quote to this challenge.
func activateAndQuote(rw io.ReadWriter, ekHandle, akHandle tpmutil.Handle, credBlob, encSecret []byte) (secret, attest, sig []byte, pcrValues map[string]string, err error) {
	if len(credBlob) < 2 || len(encSecret) < 2 {
		return nil, nil, nil, nil, errors.New("server did not return a credential activation challenge (server too old?)")
	}

	// The EK's admin role requires a policy session satisfying PolicySecret(endorsement).
	sess, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("tpm2 StartAuthSession: %w", err)
	}
	defer tpm2.FlushContext(rw, sess)
	if _, _, err := tpm2.PolicySecret(rw, tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		sess, nil, nil, nil, 0); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("tpm2 PolicySecret: %w", err)
	}

	// credactivation.Generate returns TPM2B structures; ActivateCredential re-adds the size prefix.
	secret, err = tpm2.ActivateCredentialUsingAuth(rw, []tpm2.AuthCommand{
		{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		{Session: sess, Attributes: tpm2.AttrContinueSession},
	}, akHandle, ekHandle, credBlob[2:], encSecret[2:])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("tpm2 ActivateCredential: %w", err)
	}

	pcrSel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: AttestationPCRs}
	pcrMap, err := tpm2.ReadPCRs(rw, pcrSel)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("tpm2 ReadPCRs: %w", err)
	}
	pcrValues = make(map[string]string, len(pcrMap))
	for idx, digest := range pcrMap {
		pcrValues[fmt.Sprintf("%d", idx)] = hex.EncodeToString(digest)
	}

	attest, signature, err := tpm2.Quote(rw, akHandle, "", "", secret, pcrSel, tpm2.AlgNull)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("tpm2 Quote: %w", err)
	}
	if signature == nil || signature.RSA == nil {
		return nil, nil, nil, nil, errors.New("tpm2 Quote returned no RSA signature")
	}
	return secret, attest, signature.RSA.Signature, pcrValues, nil
}
