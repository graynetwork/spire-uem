package crypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
)

// RequiredAttestationPCRs are the SHA-256 PCRs every quote must cover.
var RequiredAttestationPCRs = []int{0, 2, 4, 7}

// requiredAKAttributes are the properties of a genuine TPM-resident attestation key.
const requiredAKAttributes = tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
	tpm2.FlagRestricted | tpm2.FlagSign

// CredentialChallenge is a TPM2_MakeCredential-equivalent challenge: only the TPM holding
// the EK's private key, and holding an object with exactly this AK name, can recover Secret
// via TPM2_ActivateCredential. That is what binds the AK to the EK.
type CredentialChallenge struct {
	CredentialBlob  []byte // TPM2B_ID_OBJECT (with size prefix)
	EncryptedSecret []byte // TPM2B_ENCRYPTED_SECRET (with size prefix)
	Secret          []byte // the value the device must recover and quote over
	AKPublicPEM     string // derived from the TPM public area, not taken from the client
}

// NewCredentialChallenge validates the AK's TPM public area (TPMT_PUBLIC) and builds a
// credential-activation challenge for it, encrypted to the EK.
func NewCredentialChallenge(akPublicTPM []byte, ekPublicPEM string) (*CredentialChallenge, error) {
	if len(akPublicTPM) == 0 {
		return nil, errors.New("missing AK TPM public area")
	}
	akPub, err := tpm2.DecodePublic(akPublicTPM)
	if err != nil {
		return nil, fmt.Errorf("decode AK public area: %w", err)
	}
	if akPub.Type != tpm2.AlgRSA || akPub.NameAlg != tpm2.AlgSHA256 {
		return nil, fmt.Errorf("AK must be RSA with SHA-256 name algorithm")
	}
	if akPub.Attributes&requiredAKAttributes != requiredAKAttributes || akPub.Attributes&tpm2.FlagDecrypt != 0 {
		return nil, fmt.Errorf("AK attributes 0x%x are not a restricted, fixedTPM signing key", uint32(akPub.Attributes))
	}
	akKey, err := akPub.Key()
	if err != nil {
		return nil, fmt.Errorf("extract AK public key: %w", err)
	}
	akDER, err := x509.MarshalPKIXPublicKey(akKey)
	if err != nil {
		return nil, fmt.Errorf("marshal AK public key: %w", err)
	}
	name, err := akPub.Name()
	if err != nil {
		return nil, fmt.Errorf("compute AK name: %w", err)
	}

	ekPub, err := ParseRSAPublicKeyPEM(ekPublicPEM)
	if err != nil {
		return nil, fmt.Errorf("parse EK public key: %w", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate credential secret: %w", err)
	}
	// EK templates use AES-128 CFB, i.e. a 16-byte symmetric block.
	blob, encSecret, err := credactivation.Generate(name.Digest, ekPub, 16, secret)
	if err != nil {
		return nil, fmt.Errorf("generate credential activation challenge: %w", err)
	}

	return &CredentialChallenge{
		CredentialBlob:  blob,
		EncryptedSecret: encSecret,
		Secret:          secret,
		AKPublicPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: akDER})),
	}, nil
}

// VerifyQuote verifies a TPM2_Quote produced by the AK: the RSASSA signature, that the
// structure is a genuine TPM-generated quote, that extraData equals the challenge secret,
// that the selection covers exactly the required SHA-256 PCRs, and that the reported PCR
// values hash to the signed PCR digest. It returns the PCR values that are now proven.
func VerifyQuote(akPublicPEM string, quoteAttest, quoteSig, expectedNonce []byte, reportedPCRs map[string]string, required []int) (map[int][]byte, error) {
	if len(quoteAttest) == 0 || len(quoteSig) == 0 {
		return nil, errors.New("missing quote or signature")
	}
	if len(expectedNonce) == 0 {
		return nil, errors.New("no challenge nonce to verify against")
	}
	akPub, err := ParseRSAPublicKeyPEM(akPublicPEM)
	if err != nil {
		return nil, fmt.Errorf("parse AK public key: %w", err)
	}
	digest := sha256.Sum256(quoteAttest)
	if err := rsa.VerifyPKCS1v15(akPub, crypto.SHA256, digest[:], quoteSig); err != nil {
		return nil, fmt.Errorf("quote signature invalid: %w", err)
	}

	ad, err := tpm2.DecodeAttestationData(quoteAttest) // also enforces TPM_GENERATED magic
	if err != nil {
		return nil, fmt.Errorf("decode quote: %w", err)
	}
	if ad.Type != tpm2.TagAttestQuote || ad.AttestedQuoteInfo == nil {
		return nil, fmt.Errorf("attestation is not a quote (type 0x%x)", uint16(ad.Type))
	}
	if subtle.ConstantTimeCompare(ad.ExtraData, expectedNonce) != 1 {
		return nil, errors.New("quote extraData does not match the challenge (stale or replayed quote)")
	}

	qi := ad.AttestedQuoteInfo
	if qi.PCRSelection.Hash != tpm2.AlgSHA256 {
		return nil, errors.New("quote must cover the SHA-256 PCR bank")
	}
	selected := append([]int(nil), qi.PCRSelection.PCRs...)
	sort.Ints(selected)
	want := append([]int(nil), required...)
	sort.Ints(want)
	if len(selected) != len(want) {
		return nil, fmt.Errorf("quote covers PCRs %v, want %v", selected, want)
	}
	for i := range want {
		if selected[i] != want[i] {
			return nil, fmt.Errorf("quote covers PCRs %v, want %v", selected, want)
		}
	}

	// TPMS_QUOTE_INFO.pcrDigest = H(PCR[i0] || PCR[i1] || ...) in ascending index order.
	h := sha256.New()
	proven := make(map[int][]byte, len(selected))
	for _, idx := range selected {
		raw, ok := reportedPCRs[strconv.Itoa(idx)]
		if !ok {
			return nil, fmt.Errorf("PCR %d value missing from report", idx)
		}
		val, err := hex.DecodeString(raw)
		if err != nil || len(val) != sha256.Size {
			return nil, fmt.Errorf("PCR %d value is not a SHA-256 digest", idx)
		}
		h.Write(val)
		proven[idx] = val
	}
	if !bytes.Equal(h.Sum(nil), qi.PCRDigest) {
		return nil, errors.New("reported PCR values do not match the signed PCR digest")
	}
	return proven, nil
}

// VerifySimulatedQuote verifies the software-simulated quote used by SPIRE_SIMULATE_TPM2
// test harnesses: a JSON document {nonce, pcr_values} signed with the AK. It proves only
// freshness and self-consistency, never hardware state, so callers must accept it only
// when simulation is explicitly enabled on the server.
func VerifySimulatedQuote(akPublicPEM string, quoteAttest, quoteSig []byte, expectedNonce string, reportedPCRs map[string]string) (map[int][]byte, error) {
	if expectedNonce == "" {
		return nil, errors.New("no challenge nonce to verify against")
	}
	if err := VerifyQuoteSignature(akPublicPEM, quoteAttest, quoteSig); err != nil {
		return nil, err
	}
	var doc struct {
		Nonce     string            `json:"nonce"`
		PCRValues map[string]string `json:"pcr_values"`
	}
	if err := json.Unmarshal(quoteAttest, &doc); err != nil {
		return nil, fmt.Errorf("decode simulated quote: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(doc.Nonce), []byte(expectedNonce)) != 1 {
		return nil, errors.New("simulated quote nonce does not match the challenge")
	}
	proven := make(map[int][]byte)
	for _, idx := range RequiredAttestationPCRs {
		k := strconv.Itoa(idx)
		if doc.PCRValues[k] == "" || doc.PCRValues[k] != reportedPCRs[k] {
			return nil, fmt.Errorf("simulated quote PCR %d missing or differs from report", idx)
		}
		v, err := hex.DecodeString(doc.PCRValues[k])
		if err != nil {
			return nil, fmt.Errorf("PCR %d is not hex", idx)
		}
		proven[idx] = v
	}
	return proven, nil
}
