package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/spire-uem/spire-uem/internal/types"
)

func TestOIDCService_SettingsAndDiscovery(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OIDCDiscoveryResponse{
			Issuer:                "http://" + r.Host,
			AuthorizationEndpoint: "http://" + r.Host + "/authorize",
			TokenEndpoint:         "http://" + r.Host + "/token",
			JwksURI:               "http://" + r.Host + "/jwks.json",
			UserinfoEndpoint:      "http://" + r.Host + "/userinfo",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	initialSettings := types.SSOSettings{
		OIDCEnabled:     true,
		IssuerURL:       server.URL,
		ClientID:        "spire-client-id",
		ClientSecret:    "spire-client-secret",
		Scopes:          "openid,profile,email,groups",
		GroupsClaim:     "groups",
		AllowLocalLogin: true,
	}

	svc := NewService(initialSettings)
	if !svc.GetSettings().OIDCEnabled {
		t.Fatalf("expected OIDC to be enabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	disc, err := svc.Discover(ctx)
	if err != nil {
		t.Fatalf("unexpected discovery error: %v", err)
	}

	if disc.AuthorizationEndpoint != server.URL+"/authorize" {
		t.Errorf("expected authorization endpoint %s, got %s", server.URL+"/authorize", disc.AuthorizationEndpoint)
	}
	if disc.TokenEndpoint != server.URL+"/token" {
		t.Errorf("expected token endpoint %s, got %s", server.URL+"/token", disc.TokenEndpoint)
	}

	// Test settings update
	updatedSettings := initialSettings
	updatedSettings.ClientID = "spire-client-id-updated"
	svc.UpdateSettings(updatedSettings)
	if svc.GetSettings().ClientID != "spire-client-id-updated" {
		t.Errorf("expected updated client ID")
	}
}

func TestOIDCService_GenerateAuthURL_PKCE(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OIDCDiscoveryResponse{
			Issuer:                "http://" + r.Host,
			AuthorizationEndpoint: "http://" + r.Host + "/oauth2/auth",
			TokenEndpoint:         "http://" + r.Host + "/oauth2/token",
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	svc := NewService(types.SSOSettings{
		OIDCEnabled: true,
		IssuerURL:   server.URL,
		ClientID:    "spire-web-portal",
		Scopes:      "openid,profile,email,custom_groups",
		GroupsClaim: "custom_groups",
	})

	redirectURI := "http://localhost:8080/auth/oidc/callback"
	authURL, state, err := svc.GenerateAuthURL(context.Background(), redirectURI)
	if err != nil {
		t.Fatalf("failed to generate auth url: %v", err)
	}

	if state == "" {
		t.Fatal("expected non-empty state")
	}

	if !strings.HasPrefix(authURL, server.URL+"/oauth2/auth?") {
		t.Fatalf("expected auth URL prefix %s/oauth2/auth, got %s", server.URL, authURL)
	}

	if !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Errorf("expected S256 code challenge method in %s", authURL)
	}
	if !strings.Contains(authURL, "code_challenge=") {
		t.Errorf("expected code_challenge in %s", authURL)
	}
	if !strings.Contains(authURL, "state="+state) {
		t.Errorf("expected state=%s in %s", state, authURL)
	}
}

// fakeIdP serves discovery + JWKS for an RSA key and mints signed ID tokens.
type fakeIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{key: key, kid: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OIDCDiscoveryResponse{
			Issuer:                idp.server.URL,
			AuthorizationEndpoint: idp.server.URL + "/authorize",
			TokenEndpoint:         idp.server.URL + "/token",
			JwksURI:               idp.server.URL + "/jwks.json",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: idp.kid, Algorithm: "RS256", Use: "sig",
		}}})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *fakeIdP) sign(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", idp.kid).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOIDCService_VerifyIDToken(t *testing.T) {
	idp := newFakeIdP(t)
	svc := NewService(types.SSOSettings{OIDCEnabled: true, IssuerURL: idp.server.URL, ClientID: "spire-client", GroupsClaim: "groups"})

	base := func() map[string]any {
		return map[string]any{
			"iss": idp.server.URL, "aud": "spire-client", "sub": "oidc-user-12345",
			"email": "analyst@example.com", "name": "Security Analyst",
			"groups": []string{"SOC-Level-2", "Spire-Operators"},
			"nonce":  "n-123", "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		}
	}
	ctx := context.Background()

	claims, err := svc.VerifyIDToken(ctx, idp.sign(t, idp.key, base()), "n-123")
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims.Subject != "oidc-user-12345" || claims.Email != "analyst@example.com" || len(claims.Groups) != 2 {
		t.Errorf("unexpected claims: %+v", claims)
	}

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]func() (string, string){
		"forged signature": func() (string, string) { return idp.sign(t, otherKey, base()), "n-123" },
		"wrong audience": func() (string, string) {
			c := base()
			c["aud"] = "someone-else"
			return idp.sign(t, idp.key, c), "n-123"
		},
		"wrong issuer": func() (string, string) {
			c := base()
			c["iss"] = "https://evil.example"
			return idp.sign(t, idp.key, c), "n-123"
		},
		"expired": func() (string, string) {
			c := base()
			c["exp"] = time.Now().Add(-time.Hour).Unix()
			return idp.sign(t, idp.key, c), "n-123"
		},
		"nonce mismatch": func() (string, string) { return idp.sign(t, idp.key, base()), "other-nonce" },
		"empty nonce":    func() (string, string) { return idp.sign(t, idp.key, base()), "" },
		"unsigned payload": func() (string, string) {
			return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + ".", "n-123"
		},
		"unverified email": func() (string, string) {
			c := base()
			c["email_verified"] = false
			return idp.sign(t, idp.key, c), "n-123"
		},
	}
	for name, mk := range cases {
		tok, nonce := mk()
		if _, err := svc.VerifyIDToken(ctx, tok, nonce); err == nil {
			t.Errorf("%s: expected rejection, got success", name)
		}
	}
}

func TestOIDCService_ClaimsFromMap_GroupFallbacks(t *testing.T) {
	svc := NewService(types.SSOSettings{OIDCEnabled: true, GroupsClaim: "roles"})
	claims, err := svc.claimsFromMap(map[string]interface{}{"sub": "u1", "email": "user@test.org", "roles": "Global-Admins"})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "Global-Admins" {
		t.Errorf("expected Global-Admins group, got %v", claims.Groups)
	}
	if _, err := svc.claimsFromMap(map[string]interface{}{"email": "nosub@test.org"}); err == nil {
		t.Error("expected error for missing sub")
	}
}

func TestOIDCService_AuthURLIncludesNonce(t *testing.T) {
	idp := newFakeIdP(t)
	svc := NewService(types.SSOSettings{OIDCEnabled: true, IssuerURL: idp.server.URL, ClientID: "c"})
	authURL, state, err := svc.GenerateAuthURL(context.Background(), "http://localhost/cb")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(authURL, "nonce=") {
		t.Errorf("auth URL lacks nonce: %s", authURL)
	}
	svc.mu.RLock()
	st := svc.stateStore[state]
	svc.mu.RUnlock()
	if st.nonce == "" || !strings.Contains(authURL, "nonce="+st.nonce) {
		t.Errorf("stored nonce %q not in auth URL", st.nonce)
	}
}

func TestOIDCService_DiscoveryIssuerMismatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OIDCDiscoveryResponse{Issuer: "https://attacker.example"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	svc := NewService(types.SSOSettings{OIDCEnabled: true, IssuerURL: srv.URL})
	if _, err := svc.Discover(context.Background()); err == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestOIDCService_PKCEVerificationMath(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	expectedChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if challenge != expectedChallenge {
		t.Errorf("PKCE S256 test vector mismatch: got %s, expected %s", challenge, expectedChallenge)
	}
}
