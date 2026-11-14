package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) over HMAC-SHA1 with 6 digits and a 30-second step is implemented here
// directly on the standard library. A dedicated dependency (e.g. pquerna/otp) would add a
// transitive tree for roughly forty lines of well-specified code; the QR dependency
// (skip2/go-qrcode) is justified separately because rendering a QR matrix by hand is not.

const (
	// totpStepSeconds is the TOTP time step. 30s is the RFC 6238 default and what every
	// authenticator app assumes.
	totpStepSeconds = 30
	// totpDigits is the number of code digits. 6 is the universal default.
	totpDigits = 6
	// totpSecretBytes is the size of a freshly generated shared secret (160 bits — the
	// SHA-1 block-aligned size RFC 4226 recommends).
	totpSecretBytes = 20
)

// base32NoPad encodes TOTP secrets the way authenticator apps expect: RFC 4648 base32,
// upper-case, no padding.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a new random base32-encoded TOTP secret.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, totpSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32NoPad.EncodeToString(b), nil
}

// hotpCode computes the RFC 4226 HOTP value for a base32 secret and counter.
func hotpCode(secretBase32 string, counter uint64) (string, error) {
	key, err := base32NoPad.DecodeString(strings.ToUpper(strings.TrimSpace(secretBase32)))
	if err != nil {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod), nil
}

// TOTPStep returns the current TOTP time-step counter for a moment in time.
func TOTPStep(t time.Time) uint64 {
	return uint64(t.Unix() / totpStepSeconds)
}

// TOTPCodeAt returns the TOTP code for a given secret and time (used by tests and helpers).
func TOTPCodeAt(secretBase32 string, t time.Time) (string, error) {
	return hotpCode(secretBase32, TOTPStep(t))
}

// VerifyTOTP checks a user-supplied code against the secret, allowing a +/- 1 step skew
// (RFC 6238 §5.2). It returns whether the code matched and, when it did, the exact step
// that matched so the caller can persist it and reject replays within the window.
// lastStep is the previously consumed step (0 if none); a code at or before lastStep is
// rejected as a replay.
func VerifyTOTP(secretBase32, code string, now time.Time, lastStep uint64) (ok bool, matchedStep uint64) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false, 0
	}
	current := TOTPStep(now)
	// Check current, previous and next step to tolerate clock skew.
	for delta := int64(-1); delta <= 1; delta++ {
		step := uint64(int64(current) + delta)
		expected, err := hotpCode(secretBase32, step)
		if err != nil {
			return false, 0
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			// Reject reuse of this step or any earlier one already consumed.
			if lastStep != 0 && step <= lastStep {
				return false, 0
			}
			return true, step
		}
	}
	return false, 0
}

// BuildOTPAuthURI builds the otpauth:// provisioning URI scanned by authenticator apps.
// issuer and account label the entry; secret is the base32 shared secret.
func BuildOTPAuthURI(issuer, account, secretBase32 string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secretBase32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpStepSeconds))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
