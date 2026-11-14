package web

import (
	"testing"
	"time"
)

func TestTOTPVerifyWindowAndReplay(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)

	code, err := TOTPCodeAt(secret, now)
	if err != nil {
		t.Fatalf("code: %v", err)
	}

	// Current step verifies with no prior step consumed.
	ok, step := VerifyTOTP(secret, code, now, 0)
	if !ok {
		t.Fatal("expected current code to verify")
	}

	// Replay of the SAME step must be rejected once that step is recorded as last.
	if ok2, _ := VerifyTOTP(secret, code, now, step); ok2 {
		t.Fatal("expected replay of consumed step to be rejected")
	}

	// +/- 1 step skew tolerated.
	prev, _ := TOTPCodeAt(secret, now.Add(-totpStepSeconds*time.Second))
	if ok3, _ := VerifyTOTP(secret, prev, now, 0); !ok3 {
		t.Fatal("expected previous step within skew to verify")
	}
	next, _ := TOTPCodeAt(secret, now.Add(totpStepSeconds*time.Second))
	if ok4, _ := VerifyTOTP(secret, next, now, 0); !ok4 {
		t.Fatal("expected next step within skew to verify")
	}

	// A code two steps away must fail.
	far, _ := TOTPCodeAt(secret, now.Add(3*totpStepSeconds*time.Second))
	if ok5, _ := VerifyTOTP(secret, far, now, 0); ok5 {
		t.Fatal("expected far-future code to fail")
	}

	// Wrong length / garbage fails.
	if ok6, _ := VerifyTOTP(secret, "12345", now, 0); ok6 {
		t.Fatal("expected short code to fail")
	}
}

func TestOTPAuthURI(t *testing.T) {
	uri := BuildOTPAuthURI("SpireUEM", "alice", "ABCDEFGHIJKLMNOP")
	for _, want := range []string{"otpauth://totp/", "issuer=SpireUEM", "secret=ABCDEFGHIJKLMNOP", "digits=6", "period=30", "algorithm=SHA1"} {
		if !contains(uri, want) {
			t.Fatalf("uri %q missing %q", uri, want)
		}
	}
}

func TestRecoveryCodeSingleUseHashing(t *testing.T) {
	code, hash, err := GenerateRecoveryCode()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	// Hashing is format-insensitive (dashes/case/space stripped).
	if HashRecoveryCode(code) != hash {
		t.Fatal("hash mismatch for original code")
	}
	noDash := ""
	for _, r := range code {
		if r != '-' {
			noDash += string(r)
		}
	}
	if HashRecoveryCode(noDash) != hash {
		t.Fatal("hash should ignore formatting (dashes)")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
