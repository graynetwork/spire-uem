package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Header names on every delivery.
const (
	HeaderEventID   = "Spire-Event-Id"
	HeaderSignature = "Spire-Signature"
	SpecVersion     = "spire.v1"
)

// Sign returns the Spire-Signature header value: "t=<unix>,v1=<hex HMAC-SHA256(secret, t + "." + body)>".
func Sign(secret string, ts time.Time, body []byte) string {
	t := ts.Unix()
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", t)
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", t, hex.EncodeToString(mac.Sum(nil)))
}

// Verify checks a Spire-Signature header against body with the shared secret. It rejects a
// timestamp further than tolerance from now (replay window) and compares in constant time.
// Receivers should additionally de-duplicate on the Spire-Event-Id header.
func Verify(secret, header string, body []byte, now time.Time, tolerance time.Duration) error {
	var ts int64
	var sig string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return errors.New("malformed timestamp")
			}
			ts = n
		case "v1":
			sig = v
		}
	}
	if ts == 0 || sig == "" {
		return errors.New("missing timestamp or signature")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return errors.New("timestamp outside tolerance")
	}
	want := Sign(secret, time.Unix(ts, 0), body)
	_, wantSig, _ := strings.Cut(want, ",v1=")
	if !hmac.Equal([]byte(wantSig), []byte(sig)) {
		return errors.New("signature mismatch")
	}
	return nil
}
