package auth

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sercha-oss/sercha-core/internal/core/domain"
	"github.com/sercha-oss/sercha-core/internal/core/ports/driven"
)

// mockConnectionStore for testing
type mockConnectionStore struct {
	connections map[string]*domain.Connection
}

func newMockConnectionStore() *mockConnectionStore {
	return &mockConnectionStore{
		connections: make(map[string]*domain.Connection),
	}
}

func (m *mockConnectionStore) Save(ctx context.Context, conn *domain.Connection) error {
	m.connections[conn.ID] = conn
	return nil
}

func (m *mockConnectionStore) Get(ctx context.Context, id string) (*domain.Connection, error) {
	conn, ok := m.connections[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return conn, nil
}

func (m *mockConnectionStore) List(ctx context.Context) ([]*domain.ConnectionSummary, error) {
	return nil, nil
}

func (m *mockConnectionStore) Delete(ctx context.Context, id string) error {
	delete(m.connections, id)
	return nil
}

func (m *mockConnectionStore) GetByPlatform(ctx context.Context, platform domain.PlatformType) ([]*domain.ConnectionSummary, error) {
	return nil, nil
}

func (m *mockConnectionStore) GetByAccountID(ctx context.Context, platform domain.PlatformType, accountID string) (*domain.Connection, error) {
	return nil, nil
}

func (m *mockConnectionStore) GetByTenantID(ctx context.Context, platform domain.PlatformType, tenantID string) (*domain.Connection, error) {
	return nil, nil
}

func (m *mockConnectionStore) UpdateSecrets(ctx context.Context, id string, secrets *domain.ConnectionSecrets, expiry *time.Time) error {
	conn, ok := m.connections[id]
	if !ok {
		return domain.ErrNotFound
	}
	conn.Secrets = secrets
	conn.OAuthExpiry = expiry
	return nil
}

func (m *mockConnectionStore) UpdateLastUsed(ctx context.Context, id string) error {
	return nil
}

func TestNewTokenProviderFactory(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	if factory.connectionStore != connStore {
		t.Error("expected connection store to be set")
	}
	if factory.refreshers == nil {
		t.Error("expected refreshers map to be initialized")
	}
}

func TestRegisterRefresher_WithPlatformType(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	// Mock refresher function
	mockRefresher := func(ctx context.Context, refreshToken string) (*driven.OAuthToken, error) {
		return &driven.OAuthToken{
			AccessToken:  "new_token",
			RefreshToken: "new_refresh",
			ExpiresIn:    3600,
		}, nil
	}

	// Register refresher for GitHub platform
	factory.RegisterRefresher(domain.PlatformGitHub, mockRefresher)

	// Verify it was registered
	if factory.refreshers[domain.PlatformGitHub] == nil {
		t.Error("expected GitHub refresher to be registered")
	}

	// Register refresher for LocalFS platform
	factory.RegisterRefresher(domain.PlatformLocalFS, mockRefresher)

	// Verify it was registered
	if factory.refreshers[domain.PlatformLocalFS] == nil {
		t.Error("expected LocalFS refresher to be registered")
	}

	// Verify we have exactly 2 refreshers
	if len(factory.refreshers) != 2 {
		t.Errorf("expected 2 refreshers, got %d", len(factory.refreshers))
	}
}

func TestCreateFromConnection_OAuth2(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	// Register refresher for GitHub
	mockRefresher := func(ctx context.Context, refreshToken string) (*driven.OAuthToken, error) {
		return &driven.OAuthToken{
			AccessToken:  "refreshed_token",
			RefreshToken: "new_refresh",
			ExpiresIn:    3600,
		}, nil
	}
	factory.RegisterRefresher(domain.PlatformGitHub, mockRefresher)

	expiry := time.Now().Add(1 * time.Hour)
	conn := &domain.Connection{
		ID:           "conn-1",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethodOAuth2,
		OAuthExpiry:  &expiry,
		Secrets: &domain.ConnectionSecrets{
			AccessToken:  "access_token",
			RefreshToken: "refresh_token",
		},
	}

	provider, err := factory.CreateFromConnection(context.Background(), conn)
	if err != nil {
		t.Fatalf("CreateFromConnection() error = %v", err)
	}

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}

	// Verify it's an OAuth provider
	if provider.AuthMethod() != domain.AuthMethodOAuth2 {
		t.Errorf("expected AuthMethod OAuth2, got %s", provider.AuthMethod())
	}

	// Verify we can get a token
	token, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if token != "access_token" {
		t.Errorf("expected token 'access_token', got %s", token)
	}
}

func TestCreateFromConnection_APIKey(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	conn := &domain.Connection{
		ID:           "conn-2",
		Platform:     domain.PlatformLocalFS,
		ProviderType: domain.ProviderTypeLocalFS,
		AuthMethod:   domain.AuthMethodAPIKey,
		Secrets: &domain.ConnectionSecrets{
			APIKey: "api-key-123",
		},
	}

	provider, err := factory.CreateFromConnection(context.Background(), conn)
	if err != nil {
		t.Fatalf("CreateFromConnection() error = %v", err)
	}

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}

	// Verify it's an API Key provider
	if provider.AuthMethod() != domain.AuthMethodAPIKey {
		t.Errorf("expected AuthMethod APIKey, got %s", provider.AuthMethod())
	}

	// Verify we can get the token
	token, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if token != "api-key-123" {
		t.Errorf("expected token 'api-key-123', got %s", token)
	}
}

func TestCreateFromConnection_PAT(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	conn := &domain.Connection{
		ID:           "conn-3",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethodPAT,
		Secrets: &domain.ConnectionSecrets{
			APIKey: "ghp_pat_token",
		},
	}

	provider, err := factory.CreateFromConnection(context.Background(), conn)
	if err != nil {
		t.Fatalf("CreateFromConnection() error = %v", err)
	}

	if provider.AuthMethod() != domain.AuthMethodPAT {
		t.Errorf("expected AuthMethod PAT, got %s", provider.AuthMethod())
	}

	token, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if token != "ghp_pat_token" {
		t.Errorf("expected token 'ghp_pat_token', got %s", token)
	}
}

func TestCreateFromConnection_ServiceAccount(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	serviceAccountJSON := `{"type": "service_account", "project_id": "test"}`
	conn := &domain.Connection{
		ID:           "conn-4",
		Platform:     domain.PlatformType("google"),
		ProviderType: domain.ProviderType("google_drive"),
		AuthMethod:   domain.AuthMethodServiceAccount,
		Secrets: &domain.ConnectionSecrets{
			ServiceAccountJSON: serviceAccountJSON,
		},
	}

	provider, err := factory.CreateFromConnection(context.Background(), conn)
	if err != nil {
		t.Fatalf("CreateFromConnection() error = %v", err)
	}

	if provider.AuthMethod() != domain.AuthMethodServiceAccount {
		t.Errorf("expected AuthMethod ServiceAccount, got %s", provider.AuthMethod())
	}

	token, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if token != serviceAccountJSON {
		t.Errorf("expected service account JSON, got %s", token)
	}
}

func TestCreateFromConnection_NoSecrets(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	conn := &domain.Connection{
		ID:           "conn-5",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethodOAuth2,
		Secrets:      nil, // No secrets
	}

	_, err := factory.CreateFromConnection(context.Background(), conn)
	if err == nil {
		t.Error("expected error for connection with no secrets")
	}
}

func TestCreateFromConnection_UnsupportedAuthMethod(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	conn := &domain.Connection{
		ID:           "conn-6",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethod("unknown"),
		Secrets: &domain.ConnectionSecrets{
			AccessToken: "token",
		},
	}

	_, err := factory.CreateFromConnection(context.Background(), conn)
	if err == nil {
		t.Error("expected error for unsupported auth method")
	}
}

func TestCreate_ConnectionNotFound(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	_, err := factory.Create(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent connection")
	}
}

func TestCreate_Success(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	// Save a connection
	conn := &domain.Connection{
		ID:           "conn-7",
		Platform:     domain.PlatformLocalFS,
		ProviderType: domain.ProviderTypeLocalFS,
		AuthMethod:   domain.AuthMethodAPIKey,
		Secrets: &domain.ConnectionSecrets{
			APIKey: "test-key",
		},
	}
	_ = connStore.Save(context.Background(), conn)

	provider, err := factory.Create(context.Background(), "conn-7")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestStaticTokenProvider_GetAccessToken(t *testing.T) {
	provider := NewStaticTokenProvider("static-token", domain.AuthMethodAPIKey)

	token, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if token != "static-token" {
		t.Errorf("expected token 'static-token', got %s", token)
	}
}

func TestStaticTokenProvider_GetCredentials(t *testing.T) {
	provider := NewStaticTokenProvider("api-key-value", domain.AuthMethodAPIKey)

	creds, err := provider.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("GetCredentials() error = %v", err)
	}
	if creds.AuthMethod != domain.AuthMethodAPIKey {
		t.Errorf("expected AuthMethod APIKey, got %s", creds.AuthMethod)
	}
	if creds.APIKey != "api-key-value" {
		t.Errorf("expected APIKey 'api-key-value', got %s", creds.APIKey)
	}
}

func TestStaticTokenProvider_IsValid(t *testing.T) {
	provider := NewStaticTokenProvider("token", domain.AuthMethodAPIKey)

	if !provider.IsValid(context.Background()) {
		t.Error("expected static token provider to always be valid")
	}
}

func TestOAuthTokenProvider_GetAccessToken(t *testing.T) {
	connStore := newMockConnectionStore()
	expiry := time.Now().Add(1 * time.Hour)

	provider := NewOAuthTokenProvider(
		"conn-1",
		"access_token",
		"refresh_token",
		&expiry,
		nil,
		connStore,
	)

	token, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if token != "access_token" {
		t.Errorf("expected token 'access_token', got %s", token)
	}
}

func TestOAuthTokenProvider_IsValid_WithRefresher(t *testing.T) {
	connStore := newMockConnectionStore()
	expiry := time.Now().Add(-1 * time.Hour) // Expired

	mockRefresher := func(ctx context.Context, refreshToken string) (*driven.OAuthToken, error) {
		return &driven.OAuthToken{
			AccessToken:  "new_token",
			RefreshToken: "new_refresh",
			ExpiresIn:    3600,
		}, nil
	}

	provider := NewOAuthTokenProvider(
		"conn-1",
		"access_token",
		"refresh_token",
		&expiry,
		mockRefresher,
		connStore,
	)

	// Even with expired token, should be valid because we have a refresher
	if !provider.IsValid(context.Background()) {
		t.Error("expected provider to be valid with refresher")
	}
}

func TestOAuthTokenProvider_IsValid_WithoutRefresher(t *testing.T) {
	connStore := newMockConnectionStore()
	expiry := time.Now().Add(-1 * time.Hour) // Expired

	provider := NewOAuthTokenProvider(
		"conn-1",
		"access_token",
		"", // No refresh token
		&expiry,
		nil, // No refresher
		connStore,
	)

	// Without refresher and expired token, should not be valid
	if provider.IsValid(context.Background()) {
		t.Error("expected provider to be invalid without refresher and expired token")
	}
}

func TestOAuthTokenProvider_Refresh(t *testing.T) {
	connStore := newMockConnectionStore()

	// Save connection to store
	conn := &domain.Connection{
		ID:       "conn-1",
		Platform: domain.PlatformGitHub,
		Secrets: &domain.ConnectionSecrets{
			AccessToken:  "old_token",
			RefreshToken: "refresh_token",
		},
	}
	_ = connStore.Save(context.Background(), conn)

	expiry := time.Now().Add(2 * time.Minute) // Needs refresh (within 5 minutes)

	refreshCalled := false
	mockRefresher := func(ctx context.Context, refreshToken string) (*driven.OAuthToken, error) {
		refreshCalled = true
		if refreshToken != "refresh_token" {
			t.Errorf("expected refresh token 'refresh_token', got %s", refreshToken)
		}
		return &driven.OAuthToken{
			AccessToken:  "new_token",
			RefreshToken: "new_refresh",
			ExpiresIn:    3600,
		}, nil
	}

	provider := NewOAuthTokenProvider(
		"conn-1",
		"old_token",
		"refresh_token",
		&expiry,
		mockRefresher,
		connStore,
	)

	token, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}

	if !refreshCalled {
		t.Error("expected refresher to be called")
	}

	if token != "new_token" {
		t.Errorf("expected token 'new_token', got %s", token)
	}

	// Verify connection was updated in store
	updatedConn, _ := connStore.Get(context.Background(), "conn-1")
	if updatedConn.Secrets.AccessToken != "new_token" {
		t.Errorf("expected connection to be updated with new token")
	}
}

// TestCreate_ReturnsSameInstanceForSameConnectionID verifies that Create
// returns the exact same *TokenProvider instance for the same connectionID.
func TestCreate_ReturnsSameInstanceForSameConnectionID(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	conn := &domain.Connection{
		ID:           "c1",
		Platform:     domain.PlatformLocalFS,
		ProviderType: domain.ProviderTypeLocalFS,
		AuthMethod:   domain.AuthMethodAPIKey,
		Secrets: &domain.ConnectionSecrets{
			APIKey: "test-key",
		},
	}
	_ = connStore.Save(context.Background(), conn)

	provider1, err := factory.Create(context.Background(), "c1")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	provider2, err := factory.Create(context.Background(), "c1")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify they're the exact same instance
	if provider1 != provider2 {
		t.Error("expected same provider instance for same connectionID")
	}
}

// TestCreate_ConcurrentColdStart_OnlyOneSurvives verifies that concurrent
// calls to Create for the same connectionID converge on a single instance.
func TestCreate_ConcurrentColdStart_OnlyOneSurvives(t *testing.T) {
	connStore := newMockConnectionStore()

	// Pre-populate a valid connection
	conn := &domain.Connection{
		ID:           "c1",
		Platform:     domain.PlatformLocalFS,
		ProviderType: domain.ProviderTypeLocalFS,
		AuthMethod:   domain.AuthMethodAPIKey,
		Secrets: &domain.ConnectionSecrets{
			APIKey: "test-key",
		},
	}
	_ = connStore.Save(context.Background(), conn)

	// Create a factory
	factory := NewTokenProviderFactory(connStore)

	const goroutines = 16
	results := make([]driven.TokenProvider, goroutines)
	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for all goroutines to be ready
			p, err := factory.Create(context.Background(), "c1")
			if err != nil {
				t.Errorf("goroutine %d: Create() error = %v", idx, err)
				return
			}
			results[idx] = p
		}(i)
	}

	close(start) // Signal all goroutines to start simultaneously
	wg.Wait()

	// Verify all returned the same instance
	for i := 1; i < goroutines; i++ {
		if results[i] != results[0] {
			t.Errorf("goroutine %d returned different instance than goroutine 0", i)
		}
	}
}

// TestCreate_DifferentConnectionIDs_ReturnDifferentInstances verifies that
// different connectionIDs get different provider instances.
func TestCreate_DifferentConnectionIDs_ReturnDifferentInstances(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	conn1 := &domain.Connection{
		ID:           "c1",
		Platform:     domain.PlatformLocalFS,
		ProviderType: domain.ProviderTypeLocalFS,
		AuthMethod:   domain.AuthMethodAPIKey,
		Secrets: &domain.ConnectionSecrets{
			APIKey: "key1",
		},
	}
	conn2 := &domain.Connection{
		ID:           "c2",
		Platform:     domain.PlatformLocalFS,
		ProviderType: domain.ProviderTypeLocalFS,
		AuthMethod:   domain.AuthMethodAPIKey,
		Secrets: &domain.ConnectionSecrets{
			APIKey: "key2",
		},
	}

	_ = connStore.Save(context.Background(), conn1)
	_ = connStore.Save(context.Background(), conn2)

	provider1, err := factory.Create(context.Background(), "c1")
	if err != nil {
		t.Fatalf("Create(c1) error = %v", err)
	}

	provider2, err := factory.Create(context.Background(), "c2")
	if err != nil {
		t.Fatalf("Create(c2) error = %v", err)
	}

	if provider1 == provider2 {
		t.Error("expected different provider instances for different connectionIDs")
	}
}

// TestRemoveProvider_EvictsAndForcesReload verifies that RemoveProvider
// evicts a provider from the cache and forces a fresh load on next Create.
func TestRemoveProvider_EvictsAndForcesReload(t *testing.T) {
	var getCallCount int64

	// Custom store that counts Get calls
	connStore := &countingGetStore{
		mockConnectionStore: newMockConnectionStore(),
		getCallCount:        &getCallCount,
	}

	conn := &domain.Connection{
		ID:           "c1",
		Platform:     domain.PlatformLocalFS,
		ProviderType: domain.ProviderTypeLocalFS,
		AuthMethod:   domain.AuthMethodAPIKey,
		Secrets: &domain.ConnectionSecrets{
			APIKey: "test-key",
		},
	}
	_ = connStore.Save(context.Background(), conn)

	factory := NewTokenProviderFactory(connStore)

	// First Create should call Get once
	getCallCount = 0
	_, err := factory.Create(context.Background(), "c1")
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	if getCallCount != 1 {
		t.Errorf("first Create: Get called %d times, want 1", getCallCount)
	}

	// Second Create should NOT call Get (cached)
	getCallCount = 0
	_, err = factory.Create(context.Background(), "c1")
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}
	if getCallCount != 0 {
		t.Errorf("second Create (cached): Get called %d times, want 0", getCallCount)
	}

	// Remove the provider
	factory.RemoveProvider("c1")

	// Third Create should call Get again
	getCallCount = 0
	_, err = factory.Create(context.Background(), "c1")
	if err != nil {
		t.Fatalf("third Create() after RemoveProvider error = %v", err)
	}
	if getCallCount != 1 {
		t.Errorf("third Create (after remove): Get called %d times, want 1", getCallCount)
	}
}

// countingGetStore wraps mockConnectionStore and counts Get calls
type countingGetStore struct {
	*mockConnectionStore
	getCallCount *int64
}

func (c *countingGetStore) Get(ctx context.Context, id string) (*domain.Connection, error) {
	atomic.AddInt64(c.getCallCount, 1)
	return c.mockConnectionStore.Get(ctx, id)
}

// TestCreateFromConnection_AppOnly_HappyPath tests that CreateFromConnection
// returns a ClientCredentialsTokenProvider for an app-only connection.
func TestCreateFromConnection_AppOnly_HappyPath(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	// Register app-only config for GitHub
	configCalled := false
	factory.RegisterAppOnlyConfig(domain.PlatformGitHub, func(conn *domain.Connection) (string, string, string, ClientCredential, error) {
		configCalled = true
		return "https://token.github.com", "client_id", "scope", &ClientSecretCredential{Secret: "secret"}, nil
	})

	conn := &domain.Connection{
		ID:           "app-only-conn",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethodAppOnly,
		TenantID:     "github-org",
		AppCredentialsRef: "secret/creds",
	}

	provider, err := factory.CreateFromConnection(context.Background(), conn)
	if err != nil {
		t.Fatalf("CreateFromConnection() error = %v", err)
	}

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}

	// Verify it's a ClientCredentialsTokenProvider
	cctp, ok := provider.(*ClientCredentialsTokenProvider)
	if !ok {
		t.Errorf("expected *ClientCredentialsTokenProvider, got %T", provider)
	}

	if cctp.AuthMethod() != domain.AuthMethodAppOnly {
		t.Errorf("expected AuthMethodAppOnly, got %v", cctp.AuthMethod())
	}

	if !configCalled {
		t.Error("expected config func to be called")
	}
}

// TestCreateFromConnection_AppOnly_Caching verifies that second call to
// Create for the same app-only connection returns the same instance.
func TestCreateFromConnection_AppOnly_Caching(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	factory.RegisterAppOnlyConfig(domain.PlatformGitHub, func(conn *domain.Connection) (string, string, string, ClientCredential, error) {
		return "https://token.github.com", "client_id", "scope", &ClientSecretCredential{Secret: "secret"}, nil
	})

	conn := &domain.Connection{
		ID:           "app-only-conn",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethodAppOnly,
		TenantID:     "github-org",
	}
	_ = connStore.Save(context.Background(), conn)

	// First Create should load and cache
	provider1, err := factory.Create(context.Background(), "app-only-conn")
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}

	// Second Create should return cached instance
	provider2, err := factory.Create(context.Background(), "app-only-conn")
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}

	if provider1 != provider2 {
		t.Error("expected same provider instance from cache")
	}
}

// TestCreateFromConnection_AppOnly_NoConfigRegistered tests error when no
// app-only config is registered for the platform.
func TestCreateFromConnection_AppOnly_NoConfigRegistered(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	// Don't register any config for GitHub

	conn := &domain.Connection{
		ID:           "app-only-conn",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethodAppOnly,
		TenantID:     "github-org",
	}

	_, err := factory.CreateFromConnection(context.Background(), conn)
	if err == nil {
		t.Fatal("expected error when no app-only config registered")
	}
	if err.Error() != "no app-only config registered for platform github" {
		t.Errorf("expected specific error message, got: %v", err)
	}
}

// TestCreateFromConnection_AppOnly_ConfigReturnsError tests error propagation
// from the app-only config function.
func TestCreateFromConnection_AppOnly_ConfigReturnsError(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	factory.RegisterAppOnlyConfig(domain.PlatformGitHub, func(conn *domain.Connection) (string, string, string, ClientCredential, error) {
		return "", "", "", nil, fmt.Errorf("config resolution failed")
	})

	conn := &domain.Connection{
		ID:           "app-only-conn",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethodAppOnly,
	}

	_, err := factory.CreateFromConnection(context.Background(), conn)
	if err == nil {
		t.Fatal("expected error from config func")
	}
	if err.Error() != "resolve app-only config for github: config resolution failed" {
		t.Errorf("expected error mentioning config failure, got: %v", err)
	}
}

// TestRegisterAppOnlyConfig tests the RegisterAppOnlyConfig method.
func TestRegisterAppOnlyConfig(t *testing.T) {
	connStore := newMockConnectionStore()
	factory := NewTokenProviderFactory(connStore)

	configFunc := func(conn *domain.Connection) (string, string, string, ClientCredential, error) {
		return "https://token.example.com", "client_id", "scope", nil, nil
	}

	factory.RegisterAppOnlyConfig(domain.PlatformGitHub, configFunc)

	// Verify it was registered by checking factory state
	if factory.appOnlyConfigs[domain.PlatformGitHub] == nil {
		t.Error("expected app-only config to be registered")
	}
}
