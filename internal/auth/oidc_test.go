package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		OIDCEnabled:  true,
		IssuerURL:    server.URL,
		ClientID:     "spire-web-portal",
		Scopes:       "openid,profile,email,custom_groups",
		GroupsClaim:  "custom_groups",
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

func TestOIDCService_ParseIDTokenPayload(t *testing.T) {
	claims := map[string]any{
		"sub":    "oidc-user-12345",
		"email":  "analyst@example.com",
		"name":   "Security Analyst",
		"groups": []string{"SOC-Level-2", "Spire-Operators"},
	}
	claimsBytes, _ := json.Marshal(claims)
	b64Payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	fakeJWT := "header." + b64Payload + ".signature"

	svc := NewService(types.SSOSettings{
		OIDCEnabled: true,
		GroupsClaim: "groups",
	})

	parsed, err := svc.ParseIDTokenClaims(fakeJWT)
	if err != nil {
		t.Fatalf("failed to parse ID token payload: %v", err)
	}

	if parsed.Subject != "oidc-user-12345" {
		t.Errorf("expected sub oidc-user-12345, got %s", parsed.Subject)
	}
	if parsed.Email != "analyst@example.com" {
		t.Errorf("expected email analyst@example.com, got %s", parsed.Email)
	}
	if parsed.Name != "Security Analyst" {
		t.Errorf("expected name Security Analyst, got %s", parsed.Name)
	}
	if len(parsed.Groups) != 2 || parsed.Groups[0] != "SOC-Level-2" || parsed.Groups[1] != "Spire-Operators" {
		t.Errorf("unexpected groups: %v", parsed.Groups)
	}

	// Test single string group claim fallback
	claimsSingle := map[string]any{
		"sub":   "single-group-user",
		"email": "user@test.org",
		"roles": "Global-Admins",
	}
	claimsSingleBytes, _ := json.Marshal(claimsSingle)
	b64Single := base64.RawURLEncoding.EncodeToString(claimsSingleBytes)
	fakeJWTSingle := "header." + b64Single + ".signature"

	svcSingle := NewService(types.SSOSettings{
		OIDCEnabled: true,
		GroupsClaim: "roles",
	})

	parsedSingle, err := svcSingle.ParseIDTokenClaims(fakeJWTSingle)
	if err != nil {
		t.Fatalf("failed to parse single group token: %v", err)
	}
	if len(parsedSingle.Groups) != 1 || parsedSingle.Groups[0] != "Global-Admins" {
		t.Errorf("expected Global-Admins group, got %v", parsedSingle.Groups)
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
