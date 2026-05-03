package auth

import (
	"net/url"
	"strings"
	"testing"
)

// TestBuildAdminConsentURL_BasicComposition tests basic URL composition
func TestBuildAdminConsentURL_BasicComposition(t *testing.T) {
	endpoint := "https://login.example.com/authorize"
	clientID := "my_client_id"
	redirectURI := "https://myapp.example.com/callback"
	state := "abc123xyz"

	result, err := BuildAdminConsentURL(endpoint, clientID, redirectURI, state, nil)
	if err != nil {
		t.Fatalf("BuildAdminConsentURL() error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Parse result URL: %v", err)
	}

	q := parsed.Query()
	if q.Get("client_id") != clientID {
		t.Errorf("expected client_id=%s, got %s", clientID, q.Get("client_id"))
	}
	if q.Get("redirect_uri") != redirectURI {
		t.Errorf("expected redirect_uri=%s, got %s", redirectURI, q.Get("redirect_uri"))
	}
	if q.Get("state") != state {
		t.Errorf("expected state=%s, got %s", state, q.Get("state"))
	}
}

// TestBuildAdminConsentURL_ExtraParams tests merging of extra parameters
func TestBuildAdminConsentURL_ExtraParams(t *testing.T) {
	endpoint := "https://login.example.com/authorize"
	clientID := "client_id"
	redirectURI := "https://app.example.com/cb"
	state := "state123"

	extra := map[string]string{
		"prompt":     "admin_consent",
		"scope":      "user.read mail.read",
		"custom_key": "custom_value",
	}

	result, err := BuildAdminConsentURL(endpoint, clientID, redirectURI, state, extra)
	if err != nil {
		t.Fatalf("BuildAdminConsentURL() error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Parse result URL: %v", err)
	}

	q := parsed.Query()
	if q.Get("prompt") != "admin_consent" {
		t.Errorf("expected prompt=admin_consent, got %s", q.Get("prompt"))
	}
	if q.Get("scope") != "user.read mail.read" {
		t.Errorf("expected scope=user.read mail.read, got %s", q.Get("scope"))
	}
	if q.Get("custom_key") != "custom_value" {
		t.Errorf("expected custom_key=custom_value, got %s", q.Get("custom_key"))
	}
}

// TestBuildAdminConsentURL_SpecialCharactersEscaped tests URL encoding of special characters
func TestBuildAdminConsentURL_SpecialCharactersEscaped(t *testing.T) {
	endpoint := "https://login.example.com/authorize"
	clientID := "client_id"
	// Redirect URI with query string and special characters
	redirectURI := "https://app.example.com/callback?param1=value&param2=hello world"
	state := "state with spaces"

	result, err := BuildAdminConsentURL(endpoint, clientID, redirectURI, state, nil)
	if err != nil {
		t.Fatalf("BuildAdminConsentURL() error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Parse result URL: %v", err)
	}

	q := parsed.Query()
	// Values should be decoded when retrieved from Query()
	if q.Get("redirect_uri") != redirectURI {
		t.Errorf("expected redirect_uri=%s, got %s", redirectURI, q.Get("redirect_uri"))
	}
	if q.Get("state") != state {
		t.Errorf("expected state=%s, got %s", state, q.Get("state"))
	}
}

// TestBuildAdminConsentURL_EndpointWithExistingQuery tests appending to endpoint with existing query string
func TestBuildAdminConsentURL_EndpointWithExistingQuery(t *testing.T) {
	// Endpoint with existing query params
	endpoint := "https://login.example.com/authorize?tenant=common"
	clientID := "client_id"
	redirectURI := "https://app.example.com/cb"
	state := "state"

	result, err := BuildAdminConsentURL(endpoint, clientID, redirectURI, state, nil)
	if err != nil {
		t.Fatalf("BuildAdminConsentURL() error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Parse result URL: %v", err)
	}

	q := parsed.Query()
	if q.Get("tenant") != "common" {
		t.Errorf("expected existing tenant=common, got %s", q.Get("tenant"))
	}
	if q.Get("client_id") != clientID {
		t.Errorf("expected client_id=%s, got %s", clientID, q.Get("client_id"))
	}
}

// TestBuildAdminConsentURL_EndpointWithoutExistingQuery tests endpoint without query string
func TestBuildAdminConsentURL_EndpointWithoutExistingQuery(t *testing.T) {
	endpoint := "https://login.example.com/authorize"
	clientID := "client_id"
	redirectURI := "https://app.example.com/cb"
	state := "state"

	result, err := BuildAdminConsentURL(endpoint, clientID, redirectURI, state, nil)
	if err != nil {
		t.Fatalf("BuildAdminConsentURL() error = %v", err)
	}

	// Should use ? not & since there's no existing query
	if !strings.Contains(result, "?") {
		t.Error("expected ? in URL for query string")
	}
	if strings.Count(result, "?") > 1 {
		t.Error("expected only one ? in URL")
	}
}

// TestBuildAdminConsentURL_EmptyExtraMap tests with empty extra map
func TestBuildAdminConsentURL_EmptyExtraMap(t *testing.T) {
	endpoint := "https://login.example.com/authorize"
	clientID := "client_id"
	redirectURI := "https://app.example.com/cb"
	state := "state"
	extra := make(map[string]string)

	result, err := BuildAdminConsentURL(endpoint, clientID, redirectURI, state, extra)
	if err != nil {
		t.Fatalf("BuildAdminConsentURL() error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Parse result URL: %v", err)
	}

	q := parsed.Query()
	if q.Get("client_id") != clientID {
		t.Errorf("expected client_id=%s, got %s", clientID, q.Get("client_id"))
	}

	// Should not have trailing & or ? with no params
	if strings.HasSuffix(result, "&") || strings.HasSuffix(result, "?") {
		t.Errorf("unexpected trailing character in URL: %s", result)
	}
}

// TestBuildAdminConsentURL_NilExtraMap tests with nil extra map
func TestBuildAdminConsentURL_NilExtraMap(t *testing.T) {
	endpoint := "https://login.example.com/authorize"
	clientID := "client_id"
	redirectURI := "https://app.example.com/cb"
	state := "state"

	result, err := BuildAdminConsentURL(endpoint, clientID, redirectURI, state, nil)
	if err != nil {
		t.Fatalf("BuildAdminConsentURL() error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Parse result URL: %v", err)
	}

	q := parsed.Query()
	if q.Get("client_id") != clientID {
		t.Errorf("expected client_id=%s, got %s", clientID, q.Get("client_id"))
	}
}

// TestBuildAdminConsentURL_ReturnsParseableURL tests that result is a valid URL
func TestBuildAdminConsentURL_ReturnsParseableURL(t *testing.T) {
	endpoint := "https://login.example.com/authorize"
	clientID := "client_id"
	redirectURI := "https://app.example.com/callback?param=value"
	state := "state with special chars !@#$%"
	extra := map[string]string{
		"prompt": "admin_consent",
		"scope":  "user.read mail.read",
	}

	result, err := BuildAdminConsentURL(endpoint, clientID, redirectURI, state, extra)
	if err != nil {
		t.Fatalf("BuildAdminConsentURL() error = %v", err)
	}

	// Should be parseable as a URL
	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("expected result to be parseable URL, got error: %v", err)
	}

	// Should have valid scheme and host
	if parsed.Scheme != "https" {
		t.Errorf("expected scheme=https, got %s", parsed.Scheme)
	}
	if parsed.Host != "login.example.com" {
		t.Errorf("expected host=login.example.com, got %s", parsed.Host)
	}
	if parsed.Path != "/authorize" {
		t.Errorf("expected path=/authorize, got %s", parsed.Path)
	}
}

// TestBuildAdminConsentURL_InvalidEndpoint tests error handling for invalid endpoint
func TestBuildAdminConsentURL_InvalidEndpoint(t *testing.T) {
	result, err := BuildAdminConsentURL("invalid://url][bad", "client_id", "https://app.com/cb", "state", nil)
	if err == nil {
		t.Fatal("expected error for invalid endpoint")
	}
	if result != "" {
		t.Errorf("expected empty result on error, got %s", result)
	}
}

// TestBuildAdminConsentURL_ComplexScenario tests a complex realistic scenario
func TestBuildAdminConsentURL_ComplexScenario(t *testing.T) {
	endpoint := "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	clientID := "12345678-1234-1234-1234-123456789012"
	redirectURI := "https://myapp.azurewebsites.net/auth/callback"
	state := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

	extra := map[string]string{
		"prompt":   "admin_consent",
		"scope":    "https://graph.microsoft.com/.default",
		"response_type": "code",
	}

	result, err := BuildAdminConsentURL(endpoint, clientID, redirectURI, state, extra)
	if err != nil {
		t.Fatalf("BuildAdminConsentURL() error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Parse result URL: %v", err)
	}

	q := parsed.Query()
	if q.Get("client_id") != clientID {
		t.Errorf("expected client_id=%s, got %s", clientID, q.Get("client_id"))
	}
	if q.Get("redirect_uri") != redirectURI {
		t.Errorf("expected redirect_uri=%s, got %s", redirectURI, q.Get("redirect_uri"))
	}
	if q.Get("prompt") != "admin_consent" {
		t.Errorf("expected prompt=admin_consent, got %s", q.Get("prompt"))
	}
	if q.Get("scope") != "https://graph.microsoft.com/.default" {
		t.Errorf("expected correct scope, got %s", q.Get("scope"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("expected response_type=code, got %s", q.Get("response_type"))
	}
}

// TestBuildAdminConsentURL_ExtraParamsOverride tests that new params can override defaults
func TestBuildAdminConsentURL_ExtraParamsOverride(t *testing.T) {
	endpoint := "https://example.com/auth"
	clientID := "original_client"
	redirectURI := "https://app.com/cb"
	state := "original_state"

	// Try to override standard params via extra map
	extra := map[string]string{
		"client_id": "override_client", // Trying to override
		"state":     "override_state",   // Trying to override
	}

	result, err := BuildAdminConsentURL(endpoint, clientID, redirectURI, state, extra)
	if err != nil {
		t.Fatalf("BuildAdminConsentURL() error = %v", err)
	}

	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Parse result URL: %v", err)
	}

	q := parsed.Query()
	// The standard params (set first) might be overridden by extra params
	// depending on implementation. Both outcomes are acceptable, but we document behavior.
	// In the current implementation, extra params are set after standard ones,
	// so they would override if using Set() with same key.
	clientIDValue := q.Get("client_id")
	stateValue := q.Get("state")

	// Just verify they exist (content depends on implementation's Set behavior)
	if clientIDValue == "" {
		t.Error("expected client_id to be set")
	}
	if stateValue == "" {
		t.Error("expected state to be set")
	}
}
