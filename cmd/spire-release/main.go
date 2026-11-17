// Command spire-release signs and verifies agent update manifests with an Ed25519 release
// key held OFF the control plane. It never touches the database or any server state: it
// reads a key file and a .deb, and writes a detached <deb>.manifest.json.
//
// Subcommands:
//
//	spire-release keygen  -out DIR [-name NAME]
//	    Generate an Ed25519 release key pair. Writes <DIR>/<name>.key (0600, PKCS#8 PEM) and
//	    <DIR>/<key_id>.pub (0644, PKIX PEM). The .pub file is what you ship in the agent
//	    package under /usr/share/spire/release-keys/.
//
//	spire-release sign -key KEY.key -deb FILE.deb [-version V] [-package P] [-arch A]
//	                   [-expires-days N] [-out MANIFEST]
//	    Sign a .deb. Reads the file, computes its SHA-256 and size, and writes a signed
//	    manifest (default FILE.deb.manifest.json). The private key must be mode 0600.
//
//	spire-release verify -deb FILE.deb [-manifest M] -keys DIR [-at RFC3339]
//	    Verify a .deb against its manifest using the trust anchors in DIR, exactly as the
//	    agent does: signature, known key_id, validity window, and the file's size+sha256
//	    equal the SIGNED values.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/release"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "spire-release: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `spire-release — sign and verify agent update manifests (key held off the control plane)

Usage:
  spire-release keygen -out DIR [-name NAME]
  spire-release sign   -key KEY.key -deb FILE.deb [-version V] [-package P] [-arch A] [-expires-days N] [-out MANIFEST]
  spire-release verify -deb FILE.deb [-manifest M] -keys DIR [-at RFC3339]
`)
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "output directory for the key pair (required)")
	name := fs.String("name", "release", "base name for the private key file (<name>.key)")
	_ = fs.Parse(args)
	if strings.TrimSpace(*out) == "" {
		return fmt.Errorf("keygen: -out DIR is required")
	}

	pub, priv, err := release.GenerateKey()
	if err != nil {
		return err
	}
	keyID := release.KeyID(pub)
	privPath := filepath.Join(*out, *name+".key")
	pubPath := filepath.Join(*out, keyID+".pub")

	if _, err := os.Stat(privPath); err == nil {
		return fmt.Errorf("keygen: %s already exists; refusing to overwrite a private key", privPath)
	}
	if err := release.WritePrivateKey(privPath, priv); err != nil {
		return err
	}
	if err := release.WritePublicKey(pubPath, pub); err != nil {
		return err
	}
	fmt.Printf("key_id: %s\n", keyID)
	fmt.Printf("private key: %s (mode 0600 — keep this OFF the control plane)\n", privPath)
	fmt.Printf("public key:  %s (ship this in the agent package under /usr/share/spire/release-keys/)\n", pubPath)
	return nil
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to the Ed25519 private key (required, mode 0600)")
	debPath := fs.String("deb", "", "path to the .deb to sign (required)")
	version := fs.String("version", "", "agent version (default: parsed from the .deb filename spire-agent_<v>_<arch>.deb)")
	pkg := fs.String("package", "", "Debian package name (default: parsed from filename, else spire-agent)")
	arch := fs.String("arch", "", "Debian architecture (default: parsed from filename, else amd64)")
	expiresDays := fs.Int("expires-days", 90, "days until the manifest expires")
	out := fs.String("out", "", "output manifest path (default: <deb>.manifest.json)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*keyPath) == "" || strings.TrimSpace(*debPath) == "" {
		return fmt.Errorf("sign: -key and -deb are required")
	}
	priv, err := release.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}

	sum, size, err := hashFile(*debPath)
	if err != nil {
		return err
	}

	fv, fp, fa := parseDebName(filepath.Base(*debPath))
	v := firstNonEmpty(*version, fv)
	p := firstNonEmpty(*pkg, fp, "spire-agent")
	a := firstNonEmpty(*arch, fa, "amd64")
	if v == "" {
		return fmt.Errorf("sign: could not determine version; pass -version")
	}
	if *expiresDays <= 0 {
		return fmt.Errorf("sign: -expires-days must be positive")
	}

	now := time.Now().UTC()
	payload := release.Payload{
		Version:      v,
		Package:      p,
		Architecture: a,
		SHA256:       sum,
		Size:         size,
		IssuedAt:     now,
		ExpiresAt:    now.Add(time.Duration(*expiresDays) * 24 * time.Hour),
	}
	m, err := release.Sign(priv, payload)
	if err != nil {
		return err
	}
	data, err := release.MarshalManifest(m)
	if err != nil {
		return err
	}
	manifestPath := firstNonEmpty(*out, *debPath+".manifest.json")
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s\n", *debPath)
	fmt.Printf("  version=%s package=%s arch=%s size=%d\n", v, p, a, size)
	fmt.Printf("  sha256=%s\n", sum)
	fmt.Printf("  key_id=%s expires=%s\n", m.Payload.KeyID, m.Payload.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("  manifest=%s\n", manifestPath)
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	debPath := fs.String("deb", "", "path to the .deb (required)")
	manifestPath := fs.String("manifest", "", "manifest path (default: <deb>.manifest.json)")
	keysDir := fs.String("keys", "", "directory of trust-anchor *.pub files (required)")
	atStr := fs.String("at", "", "verify as of this RFC3339 time (default: now)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*debPath) == "" || strings.TrimSpace(*keysDir) == "" {
		return fmt.Errorf("verify: -deb and -keys are required")
	}
	mPath := firstNonEmpty(*manifestPath, *debPath+".manifest.json")
	mb, err := os.ReadFile(mPath)
	if err != nil {
		return err
	}
	m, err := release.ParseManifest(mb)
	if err != nil {
		return err
	}
	trust, loadErrs := release.LoadTrustAnchors(*keysDir)
	for _, e := range loadErrs {
		fmt.Fprintf(os.Stderr, "warning: %v\n", e)
	}
	now := time.Now().UTC()
	if strings.TrimSpace(*atStr) != "" {
		if now, err = time.Parse(time.RFC3339, *atStr); err != nil {
			return fmt.Errorf("verify: bad -at time: %w", err)
		}
	}
	payload, err := release.VerifyManifest(m, trust, now)
	if err != nil {
		return fmt.Errorf("manifest verification failed: %w", err)
	}

	sum, size, err := hashFile(*debPath)
	if err != nil {
		return err
	}
	if size != payload.Size {
		return fmt.Errorf("size mismatch: file is %d bytes, signed manifest says %d", size, payload.Size)
	}
	if sum != payload.SHA256 {
		return fmt.Errorf("sha256 mismatch: file is %s, signed manifest says %s", sum, payload.SHA256)
	}
	fmt.Printf("OK: %s matches signed manifest (version=%s key_id=%s expires=%s)\n",
		*debPath, payload.Version, payload.KeyID, payload.ExpiresAt.Format(time.RFC3339))
	return nil
}

// parseDebName parses spire-agent_<version>_<arch>.deb into (version, package, arch). Any
// component it cannot parse is returned empty.
func parseDebName(name string) (version, pkg, arch string) {
	base := strings.TrimSuffix(name, ".deb")
	parts := strings.Split(base, "_")
	if len(parts) == 3 {
		return parts[1], parts[0], parts[2]
	}
	return "", "", ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
