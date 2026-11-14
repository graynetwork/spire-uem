package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spire-uem/spire-uem/internal/types"
)

// OIDCDiscoveryResponse holds metadata returned by /.well-known/openid-configuration.
type OIDCDiscoveryResponse struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	IDTokenSigningAlgs    []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

// TokenResponse holds tokens returned by the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

// OIDCClaims represents the parsed claims extracted from the verified ID token.
type OIDCClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

// Service manages OpenID Connect Single Sign-On and JIT role provisioning.
type Service struct {
	mu           sync.RWMutex
	client       *http.Client
	discovery    *OIDCDiscoveryResponse
	discoveryAt  time.Time
	verifier     *oidc.IDTokenVerifier
	verifierFor  *OIDCDiscoveryResponse
	settings     types.SSOSettings
	stateStore   map[string]authState
	stateTimeout time.Duration
}

type authState struct {
	codeVerifier string
	redirectURI  string
	nonce        string
	createdAt    time.Time
}

// NewService creates a new OIDC authentication service.
func NewService(settings types.SSOSettings) *Service {
	return &Service{
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		settings:     settings,
		stateStore:   make(map[string]authState),
		stateTimeout: 10 * time.Minute,
	}
}

// UpdateSettings refreshes the in-memory SSO configuration and invalidates discovery cache.
func (s *Service) UpdateSettings(settings types.SSOSettings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = settings
	s.discovery = nil
	s.verifier = nil
	s.verifierFor = nil
}

// GetSettings returns a snapshot of the current SSO settings.
func (s *Service) GetSettings() types.SSOSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

// Discover fetches the OpenID configuration document from the issuer.
func (s *Service) Discover(ctx context.Context) (*OIDCDiscoveryResponse, error) {
	s.mu.RLock()
	if s.discovery != nil && time.Since(s.discoveryAt) < 1*time.Hour {
		disc := s.discovery
		s.mu.RUnlock()
		return disc, nil
	}
	issuer := strings.TrimRight(s.settings.IssuerURL, "/")
	s.mu.RUnlock()

	if issuer == "" {
		return nil, errors.New("OIDC issuer URL is not configured")
	}

	wellKnownURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute discovery request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("discovery endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var disc OIDCDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("decode discovery document: %w", err)
	}
	// The discovery document must describe the issuer we asked for (OIDC Discovery §4.3);
	// a trailing-slash difference is tolerated because providers differ on it.
	if strings.TrimRight(disc.Issuer, "/") != issuer {
		return nil, fmt.Errorf("discovery issuer %q does not match configured issuer %q", disc.Issuer, issuer)
	}

	s.mu.Lock()
	s.discovery = &disc
	s.discoveryAt = time.Now()
	s.mu.Unlock()

	return &disc, nil
}

// GenerateAuthURL builds the IdP authorization URL using PKCE (RFC 7636).
func (s *Service) GenerateAuthURL(ctx context.Context, redirectURI string) (string, string, error) {
	disc, err := s.Discover(ctx)
	if err != nil {
		return "", "", fmt.Errorf("oidc discovery: %w", err)
	}

	// 1. Generate 32-byte PKCE code_verifier
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", fmt.Errorf("generate verifier: %w", err)
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// 2. Generate S256 code_challenge
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// 3. Generate random state parameter
	stateBytes := make([]byte, 24)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", "", fmt.Errorf("generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// 4. Generate nonce, bound into the ID token by the IdP (replay protection)
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", fmt.Errorf("generate nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	s.mu.Lock()
	s.cleanOldStates()
	s.stateStore[state] = authState{
		codeVerifier: codeVerifier,
		redirectURI:  redirectURI,
		nonce:        nonce,
		createdAt:    time.Now(),
	}
	clientID := s.settings.ClientID
	scopes := s.settings.Scopes
	s.mu.Unlock()

	if scopes == "" {
		scopes = "openid profile email groups"
	}

	authURL, err := url.Parse(disc.AuthorizationEndpoint)
	if err != nil {
		return "", "", fmt.Errorf("invalid authorization endpoint URL: %w", err)
	}

	q := authURL.Query()
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("scope", scopes)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()

	return authURL.String(), state, nil
}

// ExchangeCode exchanges an authorization code and PKCE verifier for tokens.
// It returns the nonce that was bound to this state, for VerifyIDToken.
func (s *Service) ExchangeCode(ctx context.Context, code, state string) (*TokenResponse, string, error) {
	s.mu.Lock()
	st, found := s.stateStore[state]
	if found {
		delete(s.stateStore, state)
	}
	disc := s.discovery
	clientID := s.settings.ClientID
	clientSecret := s.settings.ClientSecret
	s.mu.Unlock()

	if !found || time.Since(st.createdAt) > s.stateTimeout {
		return nil, "", errors.New("invalid or expired OIDC state parameter")
	}

	if disc == nil {
		var err error
		disc, err = s.Discover(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("rediscover oidc endpoints: %w", err)
		}
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", st.redirectURI)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code_verifier", st.codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("execute token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, "", fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tok TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, "", fmt.Errorf("decode token response: %w", err)
	}

	return &tok, st.nonce, nil
}

// idTokenVerifier returns a go-oidc verifier for the current issuer, built from our own
// discovery document so the JWKS URI, issuer and signing algorithms all come from it.
func (s *Service) idTokenVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	disc, err := s.Discover(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifier != nil && s.verifierFor == disc {
		return s.verifier, nil
	}
	if disc.JwksURI == "" {
		return nil, errors.New("OIDC discovery document has no jwks_uri; cannot verify ID tokens")
	}
	provider := (&oidc.ProviderConfig{
		IssuerURL:  disc.Issuer,
		AuthURL:    disc.AuthorizationEndpoint,
		TokenURL:   disc.TokenEndpoint,
		JWKSURL:    disc.JwksURI,
		Algorithms: disc.IDTokenSigningAlgs,
	}).NewProvider(oidc.ClientContext(context.Background(), s.client))
	s.verifier = provider.Verifier(&oidc.Config{ClientID: s.settings.ClientID})
	s.verifierFor = disc
	return s.verifier, nil
}

// VerifyIDToken verifies the ID token's signature against the issuer's JWKS and checks
// iss, aud (our client_id), exp and the nonce bound at authorization time, then
// extracts the identity and group claims.
func (s *Service) VerifyIDToken(ctx context.Context, rawToken, expectedNonce string) (*OIDCClaims, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, errors.New("token response contained no id_token")
	}
	verifier, err := s.idTokenVerifier(ctx)
	if err != nil {
		return nil, fmt.Errorf("build id token verifier: %w", err)
	}
	idToken, err := verifier.Verify(oidc.ClientContext(ctx, s.client), rawToken)
	if err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}
	if expectedNonce == "" || idToken.Nonce != expectedNonce {
		return nil, errors.New("id token nonce mismatch")
	}

	var rawMap map[string]interface{}
	if err := idToken.Claims(&rawMap); err != nil {
		return nil, fmt.Errorf("decode id token claims: %w", err)
	}
	return s.claimsFromMap(rawMap)
}

// claimsFromMap extracts identity and group claims from an already-verified claim set.
func (s *Service) claimsFromMap(rawMap map[string]interface{}) (*OIDCClaims, error) {
	claims := &OIDCClaims{}
	if sub, ok := rawMap["sub"].(string); ok {
		claims.Subject = sub
	}
	if email, ok := rawMap["email"].(string); ok {
		claims.Email = email
	}
	if name, ok := rawMap["name"].(string); ok {
		claims.Name = name
	}
	if pref, ok := rawMap["preferred_username"].(string); ok {
		claims.PreferredUsername = pref
	}
	// Reject an email the IdP explicitly marks unverified. (Absent is accepted: accounts are
	// keyed on the subject, and an email is never used to link to an existing account.)
	if v, ok := rawMap["email_verified"].(bool); ok && !v {
		return nil, errors.New("IdP reports the email address as unverified")
	}

	s.mu.RLock()
	groupClaimName := s.settings.GroupsClaim
	s.mu.RUnlock()
	if groupClaimName == "" {
		groupClaimName = "groups"
	}
	claims.Groups = extractGroupsClaim(rawMap, groupClaimName)

	if claims.Subject == "" {
		return nil, errors.New("ID token is missing the 'sub' claim")
	}
	return claims, nil
}

func extractGroupsClaim(rawMap map[string]interface{}, claimName string) []string {
	var result []string
	val, ok := rawMap[claimName]
	if !ok {
		// Fallbacks
		if claimName != "groups" {
			val, ok = rawMap["groups"]
		}
		if !ok {
			val, ok = rawMap["roles"]
		}
	}

	switch v := val.(type) {
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				result = append(result, strings.TrimSpace(s))
			}
		}
	case []string:
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				result = append(result, strings.TrimSpace(s))
			}
		}
	case string:
		// Comma or space separated
		for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			if strings.TrimSpace(s) != "" {
				result = append(result, strings.TrimSpace(s))
			}
		}
	}
	return result
}

func (s *Service) cleanOldStates() {
	now := time.Now()
	for k, v := range s.stateStore {
		if now.Sub(v.createdAt) > s.stateTimeout {
			delete(s.stateStore, k)
		}
	}
}
