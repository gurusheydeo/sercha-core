package auth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sercha-oss/sercha-core/internal/core/domain"
	"github.com/sercha-oss/sercha-core/internal/core/ports/driven"
)

// countingMockStore wraps mockConnectionStore and counts UpdateSecrets calls
type countingMockStore struct {
	*mockConnectionStore
	updateSecretsCount *int64
}

func (c *countingMockStore) UpdateSecrets(ctx context.Context, id string, secrets *domain.ConnectionSecrets, expiry *time.Time) error {
	atomic.AddInt64(c.updateSecretsCount, 1)
	return c.mockConnectionStore.UpdateSecrets(ctx, id, secrets, expiry)
}

// TestGetAccessToken_ConcurrentRefresh_OnlyOneRefresherCall verifies that
// when multiple goroutines call GetAccessToken on an expired token
// simultaneously, the refresher is called exactly once.
func TestGetAccessToken_ConcurrentRefresh_OnlyOneRefresherCall(t *testing.T) {
	connStore := newMockConnectionStore()
	conn := &domain.Connection{
		ID:       "conn-1",
		Platform: domain.PlatformGitHub,
		Secrets: &domain.ConnectionSecrets{
			AccessToken:  "old_token",
			RefreshToken: "refresh_token",
		},
	}
	_ = connStore.Save(context.Background(), conn)

	// Token expired 10 minutes ago
	expiry := time.Now().Add(-10 * time.Minute)

	var refresherCallCount int64
	mockRefresher := func(ctx context.Context, refreshToken string) (*driven.OAuthToken, error) {
		atomic.AddInt64(&refresherCallCount, 1)
		// Simulate some work
		time.Sleep(50 * time.Millisecond)
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

	const goroutines = 16
	tokens := make([]string, goroutines)
	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for all goroutines to be ready
			token, err := provider.GetAccessToken(context.Background())
			if err != nil {
				t.Errorf("goroutine %d: GetAccessToken() error = %v", idx, err)
				return
			}
			tokens[idx] = token
		}(i)
	}

	close(start) // Signal all goroutines to start simultaneously
	wg.Wait()

	// Verify refresher was called exactly once
	finalCallCount := atomic.LoadInt64(&refresherCallCount)
	if finalCallCount != 1 {
		t.Errorf("refresher called %d times, want 1", finalCallCount)
	}

	// Verify all goroutines got the new token
	for i, token := range tokens {
		if token != "new_token" {
			t.Errorf("goroutine %d: got token %q, want new_token", i, token)
		}
	}
}

// TestGetAccessToken_RotatedRefreshToken_PersistedOnce verifies that
// when a refreshed token is rotated, the connection store's UpdateSecrets
// is called exactly once despite concurrent callers.
func TestGetAccessToken_RotatedRefreshToken_PersistedOnce(t *testing.T) {
	var updateSecretsCount int64

	// Custom mock that counts UpdateSecrets calls
	connStore := &countingMockStore{
		mockConnectionStore: newMockConnectionStore(),
		updateSecretsCount: &updateSecretsCount,
	}

	conn := &domain.Connection{
		ID:       "conn-1",
		Platform: domain.PlatformGitHub,
		Secrets: &domain.ConnectionSecrets{
			AccessToken:  "old_token",
			RefreshToken: "refresh_token",
		},
	}
	_ = connStore.Save(context.Background(), conn)

	// Token expired 10 minutes ago
	expiry := time.Now().Add(-10 * time.Minute)

	mockRefresher := func(ctx context.Context, refreshToken string) (*driven.OAuthToken, error) {
		time.Sleep(50 * time.Millisecond) // Simulate network delay
		return &driven.OAuthToken{
			AccessToken:  "new_token",
			RefreshToken: "new_refresh_token",
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

	const goroutines = 16
	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			_, err := provider.GetAccessToken(context.Background())
			if err != nil {
				t.Errorf("goroutine %d: GetAccessToken() error = %v", idx, err)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	// Verify UpdateSecrets was called exactly once
	finalCount := atomic.LoadInt64(&updateSecretsCount)
	if finalCount != 1 {
		t.Errorf("UpdateSecrets called %d times, want 1", finalCount)
	}

	// Verify the connection was updated with the new tokens
	updatedConn, err := connStore.Get(context.Background(), "conn-1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if updatedConn.Secrets.AccessToken != "new_token" {
		t.Errorf("AccessToken = %q, want new_token", updatedConn.Secrets.AccessToken)
	}
	if updatedConn.Secrets.RefreshToken != "new_refresh_token" {
		t.Errorf("RefreshToken = %q, want new_refresh_token", updatedConn.Secrets.RefreshToken)
	}
}

// TestGetCredentials_LockedSameAsGetAccessToken verifies that GetCredentials
// returns consistent token state with GetAccessToken (both hold the same lock).
func TestGetCredentials_LockedSameAsGetAccessToken(t *testing.T) {
	connStore := newMockConnectionStore()
	conn := &domain.Connection{
		ID:       "conn-1",
		Platform: domain.PlatformGitHub,
		Secrets: &domain.ConnectionSecrets{
			AccessToken:  "old_token",
			RefreshToken: "refresh_token",
		},
	}
	_ = connStore.Save(context.Background(), conn)

	// Token expired 10 minutes ago to trigger refresh
	expiry := time.Now().Add(-10 * time.Minute)

	mockRefresher := func(ctx context.Context, refreshToken string) (*driven.OAuthToken, error) {
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

	// Call GetAccessToken to refresh
	accessToken, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}

	// Call GetCredentials and verify it returns the same token
	creds, err := provider.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("GetCredentials() error = %v", err)
	}

	if creds.AccessToken != "new_token" {
		t.Errorf("GetCredentials.AccessToken = %q, want new_token", creds.AccessToken)
	}
	if creds.AccessToken != accessToken {
		t.Errorf("GetCredentials and GetAccessToken differ: %q != %q", creds.AccessToken, accessToken)
	}
	if creds.RefreshToken != "new_refresh" {
		t.Errorf("GetCredentials.RefreshToken = %q, want new_refresh", creds.RefreshToken)
	}
}
