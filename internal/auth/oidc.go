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

	"github.com/spire-uem/spire-uem/internal/types"
)

// OIDCDiscoveryResponse holds metadata returned by /.well-known/openid-configuration.
type OIDCDiscoveryResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
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
	settings     types.SSOSettings
	stateStore   map[string]authState
	stateTimeout time.Duration
}

type authState struct {
	codeVerifier string
	redirectURI  string
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

	s.mu.Lock()
	s.cleanOldStates()
	s.stateStore[state] = authState{
		codeVerifier: codeVerifier,
		redirectURI:  redirectURI,
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
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()

	return authURL.String(), state, nil
}

// ExchangeCode exchanges an authorization code and PKCE verifier for tokens.
func (s *Service) ExchangeCode(ctx context.Context, code, state string) (*TokenResponse, error) {
	s.mu.Lock()
	st, found := s.stateStore[state]
	if found {
		delete(s.stateStore, state)
	}
	disc := s.discovery
	clientID := s.settings.ClientID
	clientSecret := s.settings.ClientSecret
	s.mu.Unlock()

	if !found {
		return nil, errors.New("invalid or expired OIDC state parameter")
	}

	if disc == nil {
		var err error
		disc, err = s.Discover(ctx)
		if err != nil {
			return nil, fmt.Errorf("rediscover oidc endpoints: %w", err)
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
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tok TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	return &tok, nil
}

// ParseIDTokenClaims parses and extracts standard and group claims from an ID token JWT.
func (s *Service) ParseIDTokenClaims(rawToken string) (*OIDCClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT: expected 3 parts")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Attempt standard URL encoding if unpadded raw URL fails
		payloadBytes, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("decode JWT payload: %w", err)
		}
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &rawMap); err != nil {
		return nil, fmt.Errorf("unmarshal JWT payload: %w", err)
	}

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

	// Extract groups from configured claim name
	s.mu.RLock()
	groupClaimName := s.settings.GroupsClaim
	s.mu.RUnlock()
	if groupClaimName == "" {
		groupClaimName = "groups"
	}

	claims.Groups = extractGroupsClaim(rawMap, groupClaimName)

	if claims.Subject == "" && claims.Email == "" {
		return nil, errors.New("ID token payload missing both 'sub' and 'email' claims")
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
