package domain

import (
	"testing"
	"time"
)

func TestConnection_HasScope(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		scope    string
		expected bool
	}{
		{
			name:     "scope present",
			scopes:   []string{"repo", "read:user", "write:org"},
			scope:    "repo",
			expected: true,
		},
		{
			name:     "scope absent",
			scopes:   []string{"repo", "read:user"},
			scope:    "write:org",
			expected: false,
		},
		{
			name:     "empty scopes",
			scopes:   []string{},
			scope:    "repo",
			expected: false,
		},
		{
			name:     "nil scopes",
			scopes:   nil,
			scope:    "repo",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				OAuthScopes: tt.scopes,
			}
			if got := conn.HasScope(tt.scope); got != tt.expected {
				t.Errorf("HasScope(%s) = %v, want %v", tt.scope, got, tt.expected)
			}
		})
	}
}

func TestConnection_MissingScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		required []string
		expected []string
	}{
		{
			name:     "all present",
			scopes:   []string{"repo", "read:user", "write:org"},
			required: []string{"repo", "read:user"},
			expected: []string{},
		},
		{
			name:     "some missing",
			scopes:   []string{"repo"},
			required: []string{"repo", "read:user", "write:org"},
			expected: []string{"read:user", "write:org"},
		},
		{
			name:     "all missing",
			scopes:   []string{},
			required: []string{"repo", "read:user"},
			expected: []string{"repo", "read:user"},
		},
		{
			name:     "nil scopes all missing",
			scopes:   nil,
			required: []string{"repo", "read:user"},
			expected: []string{"repo", "read:user"},
		},
		{
			name:     "no required scopes",
			scopes:   []string{"repo"},
			required: []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				OAuthScopes: tt.scopes,
			}
			got := conn.MissingScopes(tt.required)
			if len(got) != len(tt.expected) {
				t.Errorf("MissingScopes() = %v, want %v", got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("MissingScopes()[%d] = %s, want %s", i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestConnection_ToSummary(t *testing.T) {
	now := time.Now()
	expiry := now.Add(1 * time.Hour)
	lastUsed := now.Add(-1 * time.Hour)

	conn := &Connection{
		ID:           "conn-123",
		Name:         "Test Connection",
		Platform:     PlatformGitHub,
		ProviderType: ProviderTypeGitHub,
		AuthMethod:   AuthMethodOAuth2,
		AccountID:    "user@example.com",
		OAuthExpiry:  &expiry,
		CreatedAt:    now,
		LastUsedAt:   &lastUsed,
		Secrets: &ConnectionSecrets{
			AccessToken:  "secret-token",
			RefreshToken: "secret-refresh",
		},
	}

	summary := conn.ToSummary()

	// Verify all fields are copied correctly
	if summary.ID != conn.ID {
		t.Errorf("ToSummary().ID = %s, want %s", summary.ID, conn.ID)
	}
	if summary.Name != conn.Name {
		t.Errorf("ToSummary().Name = %s, want %s", summary.Name, conn.Name)
	}
	if summary.Platform != conn.Platform {
		t.Errorf("ToSummary().Platform = %s, want %s", summary.Platform, conn.Platform)
	}
	if summary.ProviderType != conn.ProviderType {
		t.Errorf("ToSummary().ProviderType = %s, want %s", summary.ProviderType, conn.ProviderType)
	}
	if summary.AuthMethod != conn.AuthMethod {
		t.Errorf("ToSummary().AuthMethod = %s, want %s", summary.AuthMethod, conn.AuthMethod)
	}
	if summary.AccountID != conn.AccountID {
		t.Errorf("ToSummary().AccountID = %s, want %s", summary.AccountID, conn.AccountID)
	}
	if summary.OAuthExpiry == nil || !summary.OAuthExpiry.Equal(*conn.OAuthExpiry) {
		t.Errorf("ToSummary().OAuthExpiry = %v, want %v", summary.OAuthExpiry, conn.OAuthExpiry)
	}
	if !summary.CreatedAt.Equal(conn.CreatedAt) {
		t.Errorf("ToSummary().CreatedAt = %v, want %v", summary.CreatedAt, conn.CreatedAt)
	}
	if summary.LastUsedAt == nil || !summary.LastUsedAt.Equal(*conn.LastUsedAt) {
		t.Errorf("ToSummary().LastUsedAt = %v, want %v", summary.LastUsedAt, conn.LastUsedAt)
	}
}

func TestConnection_ToSummary_NilOptionalFields(t *testing.T) {
	now := time.Now()

	conn := &Connection{
		ID:           "conn-123",
		Name:         "Test Connection",
		Platform:     PlatformLocalFS,
		ProviderType: ProviderTypeLocalFS,
		AuthMethod:   AuthMethodAPIKey,
		CreatedAt:    now,
		// OAuthExpiry and LastUsedAt are nil
	}

	summary := conn.ToSummary()

	if summary.OAuthExpiry != nil {
		t.Errorf("ToSummary().OAuthExpiry = %v, want nil", summary.OAuthExpiry)
	}
	if summary.LastUsedAt != nil {
		t.Errorf("ToSummary().LastUsedAt = %v, want nil", summary.LastUsedAt)
	}
}

func TestConnection_NeedsRefresh(t *testing.T) {
	tests := []struct {
		name     string
		expiry   *time.Time
		expected bool
	}{
		{
			name:     "no expiry",
			expiry:   nil,
			expected: false,
		},
		{
			name: "expires in 10 minutes",
			expiry: func() *time.Time {
				t := time.Now().Add(10 * time.Minute)
				return &t
			}(),
			expected: false,
		},
		{
			name: "expires in 3 minutes (needs refresh)",
			expiry: func() *time.Time {
				t := time.Now().Add(3 * time.Minute)
				return &t
			}(),
			expected: true,
		},
		{
			name: "already expired",
			expiry: func() *time.Time {
				t := time.Now().Add(-1 * time.Minute)
				return &t
			}(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				OAuthExpiry: tt.expiry,
			}
			if got := conn.NeedsRefresh(); got != tt.expected {
				t.Errorf("NeedsRefresh() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConnection_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		expiry   *time.Time
		expected bool
	}{
		{
			name:     "no expiry",
			expiry:   nil,
			expected: false,
		},
		{
			name: "not expired",
			expiry: func() *time.Time {
				t := time.Now().Add(1 * time.Hour)
				return &t
			}(),
			expected: false,
		},
		{
			name: "expired",
			expiry: func() *time.Time {
				t := time.Now().Add(-1 * time.Minute)
				return &t
			}(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				OAuthExpiry: tt.expiry,
			}
			if got := conn.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConnection_HasSecrets(t *testing.T) {
	tests := []struct {
		name     string
		secrets  *ConnectionSecrets
		expected bool
	}{
		{
			name:     "has secrets",
			secrets:  &ConnectionSecrets{AccessToken: "token"},
			expected: true,
		},
		{
			name:     "no secrets",
			secrets:  nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				Secrets: tt.secrets,
			}
			if got := conn.HasSecrets(); got != tt.expected {
				t.Errorf("HasSecrets() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConnection_GetAccessToken(t *testing.T) {
	tests := []struct {
		name       string
		authMethod AuthMethod
		secrets    *ConnectionSecrets
		expected   string
	}{
		{
			name:       "OAuth2",
			authMethod: AuthMethodOAuth2,
			secrets:    &ConnectionSecrets{AccessToken: "oauth-token"},
			expected:   "oauth-token",
		},
		{
			name:       "API Key",
			authMethod: AuthMethodAPIKey,
			secrets:    &ConnectionSecrets{APIKey: "api-key-123"},
			expected:   "api-key-123",
		},
		{
			name:       "PAT",
			authMethod: AuthMethodPAT,
			secrets:    &ConnectionSecrets{APIKey: "pat-token"},
			expected:   "pat-token",
		},
		{
			name:       "no secrets",
			authMethod: AuthMethodOAuth2,
			secrets:    nil,
			expected:   "",
		},
		{
			name:       "unsupported method",
			authMethod: AuthMethodServiceAccount,
			secrets:    &ConnectionSecrets{ServiceAccountJSON: "{}"},
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &Connection{
				AuthMethod: tt.authMethod,
				Secrets:    tt.secrets,
			}
			if got := conn.GetAccessToken(); got != tt.expected {
				t.Errorf("GetAccessToken() = %s, want %s", got, tt.expected)
			}
		})
	}
}
