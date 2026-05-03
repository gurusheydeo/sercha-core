package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sercha-oss/sercha-core/internal/core/domain"
)

// fakeClientCredential implements ClientCredential for testing
type fakeClientCredential struct {
	formFields map[string]string
}

func newFakeClientCredential() *fakeClientCredential {
	return &fakeClientCredential{
		formFields: make(map[string]string),
	}
}

func (f *fakeClientCredential) Apply(form url.Values) error {
	form.Set("fake_field", "fake_value")
	f.formFields["fake_field"] = "fake_value"
	return nil
}

// TestClientCredentialsTokenProvider_HappyPath tests a first successful token fetch
func TestClientCredentialsTokenProvider_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		// Verify form fields
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("expected grant_type=client_credentials, got %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("client_id") != "test_client_id" {
			t.Errorf("expected client_id=test_client_id, got %q", r.Form.Get("client_id"))
		}
		if r.Form.Get("scope") != "test_scope" {
			t.Errorf("expected scope=test_scope, got %q", r.Form.Get("scope"))
		}
		if r.Form.Get("fake_field") != "fake_value" {
			t.Errorf("expected fake_field=fake_value, got %q", r.Form.Get("fake_field"))
		}

		resp := map[string]interface{}{
			"access_token": "test_token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cred := newFakeClientCredential()
	provider := NewClientCredentialsTokenProvider(
		server.URL,
		"test_client_id",
		"test_scope",
		cred,
		nil,
	)

	token, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}

	if token != "test_token" {
		t.Errorf("expected token=test_token, got %q", token)
	}

	// Verify credential was applied
	if cred.formFields["fake_field"] != "fake_value" {
		t.Error("credential was not applied to form")
	}
}

// TestClientCredentialsTokenProvider_CacheHit tests that subsequent calls use cached token
func TestClientCredentialsTokenProvider_CacheHit(t *testing.T) {
	callCount := int64(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&callCount, 1)
		resp := map[string]interface{}{
			"access_token": "cached_token",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider := NewClientCredentialsTokenProvider(
		server.URL,
		"test_client_id",
		"test_scope",
		newFakeClientCredential(),
		nil,
	)

	// First call - should hit endpoint
	token1, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("first GetAccessToken() error = %v", err)
	}
	if token1 != "cached_token" {
		t.Errorf("expected token=cached_token, got %q", token1)
	}

	count1 := atomic.LoadInt64(&callCount)
	if count1 != 1 {
		t.Errorf("expected 1 endpoint call, got %d", count1)
	}

	// Second call - should use cache
	token2, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("second GetAccessToken() error = %v", err)
	}
	if token2 != "cached_token" {
		t.Errorf("expected token=cached_token, got %q", token2)
	}

	count2 := atomic.LoadInt64(&callCount)
	if count2 != 1 {
		t.Errorf("expected still 1 endpoint call (cache hit), got %d", count2)
	}
}

// TestClientCredentialsTokenProvider_ExpiryRefetch tests that token is re-fetched when approaching expiry
func TestClientCredentialsTokenProvider_ExpiryRefetch(t *testing.T) {
	callCount := int64(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt64(&callCount, 1)
		var token string
		if count == 1 {
			token = "old_token"
		} else {
			token = "new_token"
		}
		resp := map[string]interface{}{
			"access_token": token,
			"expires_in":   3600, // Longer expiry so first call caches
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider := NewClientCredentialsTokenProvider(
		server.URL,
		"test_client_id",
		"test_scope",
		newFakeClientCredential(),
		nil,
	)

	// First call - gets old_token with 3600s expiry
	token1, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("first GetAccessToken() error = %v", err)
	}
	if token1 != "old_token" {
		t.Errorf("expected old_token, got %q", token1)
	}

	count1 := atomic.LoadInt64(&callCount)
	if count1 != 1 {
		t.Errorf("expected 1 call after first fetch, got %d", count1)
	}

	// Second call immediately - should still be cached (more than 60s remaining)
	token2, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("second GetAccessToken() error = %v", err)
	}
	if token2 != "old_token" {
		t.Errorf("expected old_token (cached), got %q", token2)
	}

	count2 := atomic.LoadInt64(&callCount)
	if count2 != 1 {
		t.Errorf("expected still 1 call after cached fetch, got %d", count2)
	}

	// Manually set expiry to be within 60s to trigger refetch on next call
	provider.mu.Lock()
	expiry := time.Now().Add(30 * time.Second)
	provider.expiry = &expiry
	provider.mu.Unlock()

	// Third call - should re-fetch because within 60s of expiry
	token3, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("third GetAccessToken() error = %v", err)
	}
	if token3 != "new_token" {
		t.Errorf("expected new_token (refetched), got %q", token3)
	}

	count3 := atomic.LoadInt64(&callCount)
	if count3 != 2 {
		t.Errorf("expected 2 endpoint calls after refetch, got %d", count3)
	}
}

// TestClientCredentialsTokenProvider_TokenEndpointError tests error handling
func TestClientCredentialsTokenProvider_TokenEndpointError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid client"))
	}))
	defer server.Close()

	provider := NewClientCredentialsTokenProvider(
		server.URL,
		"bad_client_id",
		"test_scope",
		newFakeClientCredential(),
		nil,
	)

	token, err := provider.GetAccessToken(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if token != "" {
		t.Errorf("expected empty token on error, got %q", token)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected error mentioning 401 status, got: %v", err)
	}
}

// TestClientCredentialsTokenProvider_ConcurrentCalls_Serialise tests that concurrent calls
// serialize on the mutex and only one token request is made
func TestClientCredentialsTokenProvider_ConcurrentCalls_Serialise(t *testing.T) {
	callCount := int64(0)
	inProgressCount := int64(0)
	maxConcurrent := int64(0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = atomic.AddInt64(&callCount, 1) // Track calls
		current := atomic.AddInt64(&inProgressCount, 1)

		// Track max concurrent requests
		for {
			max := atomic.LoadInt64(&maxConcurrent)
			if current <= max || atomic.CompareAndSwapInt64(&maxConcurrent, max, current) {
				break
			}
		}

		// Simulate some processing time
		time.Sleep(50 * time.Millisecond)

		resp := map[string]interface{}{
			"access_token": "shared_token",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)

		atomic.AddInt64(&inProgressCount, -1)
	}))
	defer server.Close()

	provider := NewClientCredentialsTokenProvider(
		server.URL,
		"test_client_id",
		"test_scope",
		newFakeClientCredential(),
		nil,
	)

	const goroutines = 10
	tokens := make([]string, goroutines)
	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for signal
			token, err := provider.GetAccessToken(context.Background())
			if err != nil {
				t.Errorf("goroutine %d: GetAccessToken() error = %v", idx, err)
				return
			}
			tokens[idx] = token
		}(i)
	}

	close(start) // Signal all goroutines to start
	wg.Wait()

	// Verify only one endpoint call was made
	finalCallCount := atomic.LoadInt64(&callCount)
	if finalCallCount != 1 {
		t.Errorf("expected 1 endpoint call, got %d", finalCallCount)
	}
	_ = finalCallCount // Use the variable to avoid unused declaration error if other assertions fail

	// Verify all goroutines got the token
	for i, token := range tokens {
		if token != "shared_token" {
			t.Errorf("goroutine %d: expected shared_token, got %q", i, token)
		}
	}
}

// TestClientCredentialsTokenProvider_AuthMethod tests AuthMethod returns AuthMethodAppOnly
func TestClientCredentialsTokenProvider_AuthMethod(t *testing.T) {
	provider := NewClientCredentialsTokenProvider(
		"http://example.com/token",
		"client_id",
		"scope",
		newFakeClientCredential(),
		nil,
	)

	if method := provider.AuthMethod(); method != domain.AuthMethodAppOnly {
		t.Errorf("expected AuthMethodAppOnly, got %v", method)
	}
}

// TestClientCredentialsTokenProvider_IsValid tests IsValid always returns true
func TestClientCredentialsTokenProvider_IsValid(t *testing.T) {
	provider := NewClientCredentialsTokenProvider(
		"http://example.com/token",
		"client_id",
		"scope",
		newFakeClientCredential(),
		nil,
	)

	if !provider.IsValid(context.Background()) {
		t.Error("expected IsValid() to return true")
	}
}

// TestClientCredentialsTokenProvider_GetCredentials tests GetCredentials returns proper Credentials
func TestClientCredentialsTokenProvider_GetCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"access_token": "test_token",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider := NewClientCredentialsTokenProvider(
		server.URL,
		"test_client_id",
		"test_scope",
		newFakeClientCredential(),
		nil,
	)

	creds, err := provider.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("GetCredentials() error = %v", err)
	}

	if creds.AuthMethod != domain.AuthMethodAppOnly {
		t.Errorf("expected AuthMethodAppOnly, got %v", creds.AuthMethod)
	}
	if creds.AccessToken != "test_token" {
		t.Errorf("expected AccessToken=test_token, got %q", creds.AccessToken)
	}
	if creds.TokenExpiry == nil {
		t.Error("expected TokenExpiry to be set")
	}
}

// TestClientSecretCredential_Apply tests ClientSecretCredential
func TestClientSecretCredential_Apply(t *testing.T) {
	cred := &ClientSecretCredential{Secret: "my_secret"}
	form := url.Values{}

	if err := cred.Apply(form); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if form.Get("client_secret") != "my_secret" {
		t.Errorf("expected client_secret=my_secret, got %q", form.Get("client_secret"))
	}
}

// TestClientCredentialsTokenProvider_ExpiresInAsString tests handling of expires_in as quoted string
func TestClientCredentialsTokenProvider_ExpiresInAsString(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return expires_in as a quoted string instead of a number
		response := `{"access_token": "token123", "expires_in": "7200"}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	provider := NewClientCredentialsTokenProvider(
		server.URL,
		"client_id",
		"scope",
		newFakeClientCredential(),
		nil,
	)

	token, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if token != "token123" {
		t.Errorf("expected token=token123, got %q", token)
	}

	// Verify expiry was parsed correctly
	provider.mu.Lock()
	if provider.expiry == nil {
		t.Error("expected expiry to be set")
	} else {
		remaining := time.Until(*provider.expiry)
		// Should be approximately 7200 seconds from now (allow 5 second tolerance for test execution time)
		if remaining < 7195*time.Second || remaining > 7200*time.Second {
			t.Errorf("expected expiry ~7200s from now, got %v", remaining)
		}
	}
	provider.mu.Unlock()
}

// TestClientCredentialsTokenProvider_MissingAccessToken tests error when response lacks access_token
func TestClientCredentialsTokenProvider_MissingAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := `{"expires_in": 3600}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	provider := NewClientCredentialsTokenProvider(
		server.URL,
		"client_id",
		"scope",
		newFakeClientCredential(),
		nil,
	)

	token, err := provider.GetAccessToken(context.Background())
	if err == nil {
		t.Fatal("expected error when access_token is missing")
	}
	if token != "" {
		t.Errorf("expected empty token, got %q", token)
	}
	if !strings.Contains(err.Error(), "access_token") {
		t.Errorf("expected error mentioning access_token, got: %v", err)
	}
}

// TestClientCredentialsTokenProvider_NoScope tests token fetch without scope
func TestClientCredentialsTokenProvider_NoScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		if r.Form.Get("scope") != "" {
			t.Errorf("expected no scope, got %q", r.Form.Get("scope"))
		}

		resp := map[string]interface{}{
			"access_token": "token_no_scope",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	provider := NewClientCredentialsTokenProvider(
		server.URL,
		"client_id",
		"", // empty scope
		newFakeClientCredential(),
		nil,
	)

	token, err := provider.GetAccessToken(context.Background())
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if token != "token_no_scope" {
		t.Errorf("expected token_no_scope, got %q", token)
	}
}
