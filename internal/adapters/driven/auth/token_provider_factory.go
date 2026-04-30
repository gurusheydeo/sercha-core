package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sercha-oss/sercha-core/internal/core/domain"
	"github.com/sercha-oss/sercha-core/internal/core/ports/driven"
)

// Ensure TokenProviderFactory implements the interface.
var _ driven.TokenProviderFactory = (*TokenProviderFactory)(nil)

// TokenRefresherFunc is a function type for token refresh operations.
type TokenRefresherFunc func(ctx context.Context, refreshToken string) (*driven.OAuthToken, error)

// TokenProviderFactory creates TokenProviders from connection credentials.
// It maintains a per-connection cache (providers) so that all callers sharing
// the same connectionID get the exact same *OAuthTokenProvider instance.
// This ensures that OAuth token refresh is serialised per connection: only one
// goroutine refreshes at a time, and subsequent callers see the new token
// immediately instead of racing the same refresh token.
//
// Cold-start race: if two goroutines call Create for the same connectionID
// simultaneously before either has populated the cache, both may call
// connectionStore.Get and construct a provider. Only one wins the
// LoadOrStore; the loser's instance is GC'd. This costs at most one extra
// Postgres read per connection per process lifetime and requires no
// synchronisation beyond the sync.Map itself.
type TokenProviderFactory struct {
	connectionStore driven.ConnectionStore
	refreshers      map[domain.PlatformType]TokenRefresherFunc
	providers       sync.Map // connectionID (string) -> driven.TokenProvider
}

// NewTokenProviderFactory creates a new TokenProviderFactory.
func NewTokenProviderFactory(
	connectionStore driven.ConnectionStore,
) *TokenProviderFactory {
	return &TokenProviderFactory{
		connectionStore: connectionStore,
		refreshers:      make(map[domain.PlatformType]TokenRefresherFunc),
	}
}

// RegisterRefresher registers a token refresh function for a platform type.
func (f *TokenProviderFactory) RegisterRefresher(
	platform domain.PlatformType,
	refresher TokenRefresherFunc,
) {
	f.refreshers[platform] = refresher
}

// Create returns a TokenProvider for the given connectionID.
//
// If a provider for connectionID already exists in the process-level cache,
// it is returned immediately (O(1), no I/O). Otherwise the connection is
// loaded from the store, a new provider is constructed, and the result is
// stored via LoadOrStore so concurrent callers converge on a single instance.
func (f *TokenProviderFactory) Create(ctx context.Context, connectionID string) (driven.TokenProvider, error) {
	if v, ok := f.providers.Load(connectionID); ok {
		return v.(driven.TokenProvider), nil
	}

	conn, err := f.connectionStore.Get(ctx, connectionID)
	if err != nil {
		return nil, fmt.Errorf("get connection: %w", err)
	}
	if conn == nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrConnectionNotFound, connectionID)
	}

	provider, err := f.CreateFromConnection(ctx, conn)
	if err != nil {
		return nil, err
	}

	// LoadOrStore: if a concurrent goroutine beat us here, discard our newly
	// constructed provider and return the winner's instance instead.
	actual, _ := f.providers.LoadOrStore(connectionID, provider)
	return actual.(driven.TokenProvider), nil
}

// RemoveProvider evicts the cached provider for a connection. It should be
// called by ConnectionService.Delete after the underlying connection row is
// removed, to prevent stale token state from persisting in memory.
//
// RemoveProvider is a concrete-only method and does not appear on the
// driven.TokenProviderFactory port interface — callers that only hold the
// interface are unaffected.
func (f *TokenProviderFactory) RemoveProvider(connectionID string) {
	f.providers.Delete(connectionID)
}

// CreateFromConnection creates a TokenProvider from a connection directly.
// Use this when you already have the connection loaded. The returned provider
// is NOT inserted into the per-connection cache — it is a fresh instance
// scoped to the caller's use (e.g. OAuth callback flows that have the
// connection in hand before it is registered in the cache).
func (f *TokenProviderFactory) CreateFromConnection(ctx context.Context, conn *domain.Connection) (driven.TokenProvider, error) {
	if conn.Secrets == nil {
		return nil, fmt.Errorf("connection has no secrets: %s", conn.ID)
	}

	switch conn.AuthMethod {
	case domain.AuthMethodOAuth2:
		refresher := f.refreshers[domain.PlatformFor(conn.ProviderType)]
		return NewOAuthTokenProvider(
			conn.ID,
			conn.Secrets.AccessToken,
			conn.Secrets.RefreshToken,
			conn.OAuthExpiry,
			refresher,
			f.connectionStore,
		), nil

	case domain.AuthMethodAPIKey:
		return NewStaticTokenProvider(conn.Secrets.APIKey, domain.AuthMethodAPIKey), nil

	case domain.AuthMethodPAT:
		token := conn.Secrets.APIKey
		if token == "" {
			token = conn.Secrets.AccessToken
		}
		return NewStaticTokenProvider(token, domain.AuthMethodPAT), nil

	case domain.AuthMethodServiceAccount:
		// Service accounts typically use the service account JSON as-is
		return NewStaticTokenProvider(conn.Secrets.ServiceAccountJSON, domain.AuthMethodServiceAccount), nil

	default:
		return nil, fmt.Errorf("%w: %s", domain.ErrUnsupportedAuthMethod, conn.AuthMethod)
	}
}

// StaticTokenProvider implements TokenProvider for non-OAuth credentials.
// Used for API keys, PATs, and service accounts.
type StaticTokenProvider struct {
	token      string
	authMethod domain.AuthMethod
}

// NewStaticTokenProvider creates a token provider for static credentials.
func NewStaticTokenProvider(token string, authMethod domain.AuthMethod) *StaticTokenProvider {
	return &StaticTokenProvider{
		token:      token,
		authMethod: authMethod,
	}
}

// GetAccessToken returns the static token.
func (p *StaticTokenProvider) GetAccessToken(ctx context.Context) (string, error) {
	return p.token, nil
}

// GetCredentials returns nil for static tokens - use GetAccessToken instead.
func (p *StaticTokenProvider) GetCredentials(ctx context.Context) (*domain.Credentials, error) {
	return &domain.Credentials{
		AuthMethod: p.authMethod,
		APIKey:     p.token,
	}, nil
}

// AuthMethod returns the authentication method.
func (p *StaticTokenProvider) AuthMethod() domain.AuthMethod {
	return p.authMethod
}

// IsValid returns true - static credentials don't expire.
func (p *StaticTokenProvider) IsValid(ctx context.Context) bool {
	return true
}

// OAuthTokenProvider implements TokenProvider for OAuth2 credentials. It is
// intended to be shared across all consumers of the same connectionID within
// the process — TokenProviderFactory.Create ensures exactly one instance exists
// per connection. The embedded mutex serialises token refresh: while one caller
// is executing the HTTP round-trip to the token endpoint (typically ~200ms),
// other callers for the same connection block on the lock and then see the
// fresh token without issuing a second refresh. This prevents the token-endpoint
// race that occurs when N concurrent goroutines each hold a stale token and all
// decide to refresh simultaneously, causing Microsoft to rotate the refresh token
// and invalidate N-1 of the requests.
//
// The mutex is held for the entire duration of the refresh HTTP call. This is
// an intentional design choice: the alternative (generation counters or
// refresh-in-flight channels) adds significantly more code for the same
// outcome. Document this explicitly so future readers do not reach for a
// singleflight rewrite without considering the trade-off.
//
// Token state divergence: if anything mutates the connection's secrets in
// Postgres without going through refreshLocked (e.g. a direct DB write),
// the in-memory provider will go stale until the process restarts or
// RemoveProvider is called and Create re-loads the connection.
type OAuthTokenProvider struct {
	mu              sync.Mutex // guards accessToken, refreshToken, expiry
	connectionID    string
	accessToken     string
	refreshToken    string
	expiry          *time.Time
	refresher       TokenRefresherFunc
	connectionStore driven.ConnectionStore
}

// NewOAuthTokenProvider creates a token provider for OAuth credentials.
func NewOAuthTokenProvider(
	connectionID string,
	accessToken string,
	refreshToken string,
	expiry *time.Time,
	refresher TokenRefresherFunc,
	connectionStore driven.ConnectionStore,
) *OAuthTokenProvider {
	return &OAuthTokenProvider{
		connectionID:    connectionID,
		accessToken:     accessToken,
		refreshToken:    refreshToken,
		expiry:          expiry,
		refresher:       refresher,
		connectionStore: connectionStore,
	}
}

// GetAccessToken returns a valid access token, refreshing if needed.
// It holds mu for the duration of a refresh so that concurrent callers
// serialise: the second caller blocks until the first refresh completes,
// then sees needsRefresh() == false and skips a redundant refresh.
func (p *OAuthTokenProvider) GetAccessToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.needsRefresh() {
		if err := p.refreshLocked(ctx); err != nil {
			return "", fmt.Errorf("refresh token: %w", err)
		}
	}
	return p.accessToken, nil
}

// GetCredentials returns credentials for OAuth.
// It holds mu for the same reason as GetAccessToken.
func (p *OAuthTokenProvider) GetCredentials(ctx context.Context) (*domain.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.needsRefresh() {
		if err := p.refreshLocked(ctx); err != nil {
			return nil, fmt.Errorf("refresh token: %w", err)
		}
	}
	return &domain.Credentials{
		AuthMethod:   domain.AuthMethodOAuth2,
		AccessToken:  p.accessToken,
		RefreshToken: p.refreshToken,
		TokenExpiry:  p.expiry,
	}, nil
}

// AuthMethod returns OAuth2.
func (p *OAuthTokenProvider) AuthMethod() domain.AuthMethod {
	return domain.AuthMethodOAuth2
}

// IsValid checks if credentials are valid (not expired or can be refreshed).
//
// This method is lock-free and intentionally so: its contract is best-effort
// ("has a valid token or can be refreshed"). A concurrent refresh may flip
// isExpired() from true to false while IsValid runs; the race only makes the
// result more conservative (returns true when the token was just refreshed),
// never incorrectly false. Callers that need a guaranteed-valid token must
// call GetAccessToken instead.
func (p *OAuthTokenProvider) IsValid(ctx context.Context) bool {
	// If we have a refresh token and refresher, we can always refresh
	if p.refreshToken != "" && p.refresher != nil {
		return true
	}
	// Otherwise, check if access token is still valid
	return !p.isExpired()
}

// needsRefresh returns true if the token should be refreshed.
// MUST be called with mu held.
func (p *OAuthTokenProvider) needsRefresh() bool {
	if p.expiry == nil {
		return false
	}
	// Refresh if expiring within 5 minutes
	return time.Until(*p.expiry) < 5*time.Minute
}

// isExpired returns true if the token has expired.
// MUST be called with mu held.
func (p *OAuthTokenProvider) isExpired() bool {
	if p.expiry == nil {
		return false
	}
	return time.Now().After(*p.expiry)
}

// refreshLocked refreshes the access token using the refresh token.
// Caller MUST hold mu. The mutex is held for the entire HTTP round-trip
// to the token endpoint so that concurrent callers serialise on this
// operation. See OAuthTokenProvider for the rationale.
func (p *OAuthTokenProvider) refreshLocked(ctx context.Context) error {
	if p.refresher == nil {
		return fmt.Errorf("no token refresher configured")
	}
	if p.refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	tokens, err := p.refresher(ctx, p.refreshToken)
	if err != nil {
		return err
	}

	// Update local state
	p.accessToken = tokens.AccessToken
	if tokens.RefreshToken != "" {
		p.refreshToken = tokens.RefreshToken
	}
	if tokens.ExpiresIn > 0 {
		expiry := time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
		p.expiry = &expiry
	}

	// Update connection store so the new tokens survive a process restart.
	// Exactly one writer per connection at a time because mu is held.
	// Ignore error — we have the tokens locally; persistence failure is non-fatal.
	if p.connectionStore != nil {
		secrets := &domain.ConnectionSecrets{
			AccessToken:  p.accessToken,
			RefreshToken: p.refreshToken,
		}
		_ = p.connectionStore.UpdateSecrets(ctx, p.connectionID, secrets, p.expiry)
	}

	return nil
}
