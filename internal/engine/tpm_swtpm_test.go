package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	spirecrypto "github.com/spire-uem/spire-uem/internal/crypto"
)

// startSWTPM launches a throwaway swtpm and returns a connection to its TPM command port.
// The test is skipped when swtpm is not installed.
func startSWTPM(t *testing.T) net.Conn {
	t.Helper()
	bin, err := exec.LookPath("swtpm")
	if err != nil {
		t.Skip("swtpm not installed; skipping hardware-path attestation test")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	cmd := exec.Command(bin, "socket", "--tpm2", "--terminate",
		"--tpmstate", "dir="+t.TempDir(),
		"--server", fmt.Sprintf("type=tcp,port=%d,bindaddr=127.0.0.1", port),
		"--ctrl", fmt.Sprintf("type=tcp,port=%d,bindaddr=127.0.0.1", port+1),
		"--flags", "not-need-init,startup-clear")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	// swtpm's AppArmor profile may refuse signals from the test process, so shut it down
	// through its control channel (and --terminate on data-connection loss), with a bound.
	t.Cleanup(func() {
		_ = exec.Command("swtpm_ioctl", "-s", "--tcp", fmt.Sprintf("127.0.0.1:%d", port+1)).Run()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Logf("swtpm pid %d did not exit within 5s", cmd.Process.Pid)
		}
	})

	var conn net.Conn
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect to swtpm: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestHardwareAttestation_CredentialActivationAndQuote(t *testing.T) {
	rw := startSWTPM(t)

	ekH, akH, ekPEM, akPEM, akPublicTPM, err := createAttestationKeys(rw)
	if err != nil {
		t.Fatalf("createAttestationKeys: %v", err)
	}
	defer tpm2.FlushContext(rw, ekH)
	defer tpm2.FlushContext(rw, akH)

	// Server side: challenge bound to this AK's name, encrypted to the EK.
	ch, err := spirecrypto.NewCredentialChallenge(akPublicTPM, ekPEM)
	if err != nil {
		t.Fatalf("NewCredentialChallenge: %v", err)
	}
	if strings.TrimSpace(ch.AKPublicPEM) != strings.TrimSpace(akPEM) {
		t.Fatalf("server-derived AK PEM differs from agent AK PEM")
	}

	// Device side: activate + quote.
	secret, attest, sig, pcrs, err := activateAndQuote(rw, ekH, akH, ch.CredentialBlob, ch.EncryptedSecret)
	if err != nil {
		t.Fatalf("activateAndQuote: %v", err)
	}
	if hex.EncodeToString(secret) != hex.EncodeToString(ch.Secret) {
		t.Fatal("activated secret differs from the server secret")
	}

	// Server side: verify.
	proven, err := spirecrypto.VerifyQuote(ch.AKPublicPEM, attest, sig, ch.Secret, pcrs, spirecrypto.RequiredAttestationPCRs)
	if err != nil {
		t.Fatalf("VerifyQuote rejected a genuine quote: %v", err)
	}
	if len(proven) != len(spirecrypto.RequiredAttestationPCRs) {
		t.Fatalf("expected %d proven PCRs, got %d", len(spirecrypto.RequiredAttestationPCRs), len(proven))
	}

	t.Run("tampered PCR report is rejected", func(t *testing.T) {
		bad := map[string]string{}
		for k, v := range pcrs {
			bad[k] = v
		}
		bad["7"] = strings.Repeat("ab", 32)
		if _, err := spirecrypto.VerifyQuote(ch.AKPublicPEM, attest, sig, ch.Secret, bad, spirecrypto.RequiredAttestationPCRs); err == nil {
			t.Fatal("expected PCR digest mismatch")
		}
	})
	t.Run("replayed quote against a new challenge is rejected", func(t *testing.T) {
		other := make([]byte, 32)
		_, _ = rand.Read(other)
		if _, err := spirecrypto.VerifyQuote(ch.AKPublicPEM, attest, sig, other, pcrs, spirecrypto.RequiredAttestationPCRs); err == nil {
			t.Fatal("expected extraData mismatch")
		}
	})
	t.Run("quote signed by a different key is rejected", func(t *testing.T) {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		otherPEM := "-----BEGIN PUBLIC KEY-----\n" + wrap64(der) + "-----END PUBLIC KEY-----\n"
		if _, err := spirecrypto.VerifyQuote(otherPEM, attest, sig, ch.Secret, pcrs, spirecrypto.RequiredAttestationPCRs); err == nil {
			t.Fatal("expected signature failure")
		}
	})
	t.Run("credential bound to a different AK name cannot be activated", func(t *testing.T) {
		// A software AK the attacker controls: the TPM refuses to release the secret
		// because the credential's name binding does not match the loaded AK.
		pub, _ := tpm2.DecodePublic(akPublicTPM)
		pub.RSAParameters.ModulusRaw = make([]byte, 256)
		pub.RSAParameters.ModulusRaw[0] = 0xC3
		name, _ := pub.Name()
		ekKey, _ := spirecrypto.ParseRSAPublicKeyPEM(ekPEM)
		blob, enc, err := credactivation.Generate(name.Digest, ekKey, 16, ch.Secret)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := activateAndQuote(rw, ekH, akH, blob, enc); err == nil {
			t.Fatal("expected ActivateCredential to fail for a credential bound to another AK")
		}
	})
}

func TestNewCredentialChallenge_RejectsNonRestrictedKey(t *testing.T) {
	tmpl := akTemplateRSA()
	tmpl.Attributes &^= tpm2.FlagRestricted
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl.RSAParameters.ModulusRaw = k.N.Bytes()
	enc, err := tmpl.Encode()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	ekPEM := "-----BEGIN PUBLIC KEY-----\n" + wrap64(der) + "-----END PUBLIC KEY-----\n"
	if _, err := spirecrypto.NewCredentialChallenge(enc, ekPEM); err == nil {
		t.Fatal("expected unrestricted AK to be rejected")
	}
}

func wrap64(der []byte) string {
	const line = 64
	b64 := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	for len(b64) > line {
		sb.WriteString(b64[:line] + "\n")
		b64 = b64[line:]
	}
	sb.WriteString(b64 + "\n")
	return sb.String()
}
