package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sercha-oss/sercha-core/internal/core/domain"
)

// ClientCredential populates the credential fields of an OAuth 2.0
// client_credentials token request form. Implementations choose between
// a client secret and a signed JWT client assertion.
type ClientCredential interface {
	// Apply sets the credential-specific form fields on v.
	// For a secret credential: sets "client_secret".
	// For a certificate credential: sets "client_assertion" and
	// "client_assertion_type".
	Apply(form url.Values) error
}

// ClientSecretCredential is a ClientCredential backed by a shared secret.
type ClientSecretCredential struct {
	Secret string
}

// Apply sets the client_secret form field.
func (c *ClientSecretCredential) Apply(form url.Values) error {
	form.Set("client_secret", c.Secret)
	return nil
}

// ClientCredentialsTokenProvider fetches access tokens using the
// client_credentials grant (app-only flow). Tokens are cached in memory
// and re-fetched when fewer than 60 seconds remain before expiry. Because
// the credential is application-scoped rather than user-scoped, fetched
// tokens are never written back to the connection store.
//
// The embedded mutex serialises concurrent calls to GetAccessToken so that
// only one HTTP round-trip to the token endpoint occurs at a time per
// provider instance.
type ClientCredentialsTokenProvider struct {
	mu             sync.Mutex
	tokenEndpoint  string
	clientID       string
	clientCred     ClientCredential
	scope          string
	accessToken    string
	expiry         *time.Time
	httpClient     *http.Client
}

// NewClientCredentialsTokenProvider creates a ClientCredentialsTokenProvider.
// If httpClient is nil, http.DefaultClient is used.
func NewClientCredentialsTokenProvider(
	tokenEndpoint, clientID, scope string,
	cred ClientCredential,
	httpClient *http.Client,
) *ClientCredentialsTokenProvider {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &ClientCredentialsTokenProvider{
		tokenEndpoint: tokenEndpoint,
		clientID:      clientID,
		clientCred:    cred,
		scope:         scope,
		httpClient:    httpClient,
	}
}

// GetAccessToken returns a valid access token, fetching a new one when the
// cached token is absent or within 60 seconds of expiry.
func (p *ClientCredentialsTokenProvider) GetAccessToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.accessToken != "" && p.expiry != nil && time.Until(*p.expiry) > 60*time.Second {
		return p.accessToken, nil
	}

	if err := p.fetchLocked(ctx); err != nil {
		return "", err
	}
	return p.accessToken, nil
}

// GetCredentials fetches (or returns cached) credentials as a domain.Credentials
// value with AuthMethod set to AuthMethodAppOnly.
func (p *ClientCredentialsTokenProvider) GetCredentials(ctx context.Context) (*domain.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.accessToken != "" && p.expiry != nil && time.Until(*p.expiry) > 60*time.Second {
		return p.buildCredentials(), nil
	}

	if err := p.fetchLocked(ctx); err != nil {
		return nil, err
	}
	return p.buildCredentials(), nil
}

// AuthMethod returns AuthMethodAppOnly.
func (p *ClientCredentialsTokenProvider) AuthMethod() domain.AuthMethod {
	return domain.AuthMethodAppOnly
}

// IsValid returns true. App-only tokens can always be re-fetched from the
// token endpoint; there is no refresh-token that can expire or be revoked.
func (p *ClientCredentialsTokenProvider) IsValid(_ context.Context) bool {
	return true
}

// buildCredentials constructs a Credentials value from cached state.
// MUST be called with mu held.
func (p *ClientCredentialsTokenProvider) buildCredentials() *domain.Credentials {
	return &domain.Credentials{
		AuthMethod:  domain.AuthMethodAppOnly,
		AccessToken: p.accessToken,
		TokenExpiry: p.expiry,
	}
}

// fetchLocked posts to the token endpoint and updates the cached token.
// MUST be called with mu held.
func (p *ClientCredentialsTokenProvider) fetchLocked(ctx context.Context) error {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", p.clientID)
	if p.scope != "" {
		form.Set("scope", p.scope)
	}
	if err := p.clientCred.Apply(form); err != nil {
		return fmt.Errorf("apply credential: %w", err)
	}

	encoded := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenEndpoint, strings.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(encoded))

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("token endpoint request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}

	// Use a generic map so we can handle expires_in as either string or number.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("parse token response: %w", err)
	}

	atRaw, ok := raw["access_token"]
	if !ok {
		return fmt.Errorf("token response missing access_token")
	}
	var accessToken string
	if err := json.Unmarshal(atRaw, &accessToken); err != nil {
		return fmt.Errorf("parse access_token: %w", err)
	}

	p.accessToken = accessToken

	if eiRaw, ok := raw["expires_in"]; ok {
		var expiresIn int
		// Try number first, then quoted string.
		if err := json.Unmarshal(eiRaw, &expiresIn); err == nil {
			expiry := time.Now().Add(time.Duration(expiresIn) * time.Second)
			p.expiry = &expiry
		} else {
			var s string
			if err2 := json.Unmarshal(eiRaw, &s); err2 == nil {
				if n, err3 := strconv.Atoi(s); err3 == nil {
					expiry := time.Now().Add(time.Duration(n) * time.Second)
					p.expiry = &expiry
				}
			}
		}
	}

	return nil
}

