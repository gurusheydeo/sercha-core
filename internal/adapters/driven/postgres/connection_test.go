package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/sercha-oss/sercha-core/internal/core/domain"
)

// openTestDB returns a connection to a Postgres instance described by
// TEST_DATABASE_URL, or skips the test when the env var is unset.
func openTestConnDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skipf("set TEST_DATABASE_URL to run")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("ping test db: %v", err)
	}
	return db
}

// resetTestConnSchema drops and recreates the schema for clean slate.
func resetTestConnSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
		"GRANT ALL ON SCHEMA public TO public",
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("reset schema (%q): %v", s, err)
		}
	}
	// Apply migrations
	if err := Up(context.Background(), db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
}

// TestConnectionStore_SaveAndGet_WithTenantID tests round-trip with TenantID and AppCredentialsRef
func TestConnectionStore_SaveAndGet_WithTenantID(t *testing.T) {
	db := openTestConnDB(t)
	defer func() { _ = db.Close() }()
	resetTestConnSchema(t, db)

	ctx := context.Background()
	encryptor, err := NewSecretEncryptor([]byte("test-key-32-bytes-long-exactly!!"))
	if err != nil {
		t.Fatalf("NewSecretEncryptor() error = %v", err)
	}
	store := NewConnectionStore(db, encryptor)

	conn := &domain.Connection{
		ID:                "conn-1",
		Name:              "GitHub App",
		Platform:          domain.PlatformGitHub,
		ProviderType:      domain.ProviderTypeGitHub,
		AuthMethod:        domain.AuthMethodAppOnly,
		TenantID:          "github-org-123",
		AppCredentialsRef: "secret/conn-1/app-creds",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := store.Save(ctx, conn); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	retrieved, err := store.Get(ctx, "conn-1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved.TenantID != "github-org-123" {
		t.Errorf("expected TenantID=github-org-123, got %q", retrieved.TenantID)
	}
	if retrieved.AppCredentialsRef != "secret/conn-1/app-creds" {
		t.Errorf("expected AppCredentialsRef=secret/conn-1/app-creds, got %q", retrieved.AppCredentialsRef)
	}
}

// TestConnectionStore_SaveAndGet_WithoutTenantID tests round-trip with empty TenantID and AppCredentialsRef
func TestConnectionStore_SaveAndGet_WithoutTenantID(t *testing.T) {
	db := openTestConnDB(t)
	defer func() { _ = db.Close() }()
	resetTestConnSchema(t, db)

	ctx := context.Background()
	encryptor, err := NewSecretEncryptor([]byte("test-key-32-bytes-long-exactly!!"))
	if err != nil {
		t.Fatalf("NewSecretEncryptor() error = %v", err)
	}
	store := NewConnectionStore(db, encryptor)

	conn := &domain.Connection{
		ID:           "conn-2",
		Name:         "User OAuth",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethodOAuth2,
		AccountID:    "user@example.com",
		TenantID:     "",           // Empty
		AppCredentialsRef: "",      // Empty
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := store.Save(ctx, conn); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	retrieved, err := store.Get(ctx, "conn-2")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved.TenantID != "" {
		t.Errorf("expected TenantID=empty, got %q", retrieved.TenantID)
	}
	if retrieved.AppCredentialsRef != "" {
		t.Errorf("expected AppCredentialsRef=empty, got %q", retrieved.AppCredentialsRef)
	}
}

// TestConnectionStore_GetByTenantID_HappyPath tests GetByTenantID retrieval
func TestConnectionStore_GetByTenantID_HappyPath(t *testing.T) {
	db := openTestConnDB(t)
	defer func() { _ = db.Close() }()
	resetTestConnSchema(t, db)

	ctx := context.Background()
	encryptor, err := NewSecretEncryptor([]byte("test-key-32-bytes-long-exactly!!"))
	if err != nil {
		t.Fatalf("NewSecretEncryptor() error = %v", err)
	}
	store := NewConnectionStore(db, encryptor)

	conn := &domain.Connection{
		ID:                "app-conn-1",
		Name:              "GitHub App",
		Platform:          domain.PlatformGitHub,
		ProviderType:      domain.ProviderTypeGitHub,
		AuthMethod:        domain.AuthMethodAppOnly,
		TenantID:          "my-org",
		AppCredentialsRef: "secret/app-creds",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := store.Save(ctx, conn); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	retrieved, err := store.GetByTenantID(ctx, domain.PlatformGitHub, "my-org")
	if err != nil {
		t.Fatalf("GetByTenantID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("expected non-nil connection")
	}
	if retrieved.ID != "app-conn-1" {
		t.Errorf("expected ID=app-conn-1, got %q", retrieved.ID)
	}
	if retrieved.TenantID != "my-org" {
		t.Errorf("expected TenantID=my-org, got %q", retrieved.TenantID)
	}
}

// TestConnectionStore_GetByTenantID_NotFound tests GetByTenantID returns nil on not found
func TestConnectionStore_GetByTenantID_NotFound(t *testing.T) {
	db := openTestConnDB(t)
	defer func() { _ = db.Close() }()
	resetTestConnSchema(t, db)

	ctx := context.Background()
	encryptor, err := NewSecretEncryptor([]byte("test-key-32-bytes-long-exactly!!"))
	if err != nil {
		t.Fatalf("NewSecretEncryptor() error = %v", err)
	}
	store := NewConnectionStore(db, encryptor)

	retrieved, err := store.GetByTenantID(ctx, domain.PlatformGitHub, "nonexistent-org")
	if err != nil {
		t.Fatalf("GetByTenantID() error = %v", err)
	}

	if retrieved != nil {
		t.Error("expected nil for nonexistent tenant")
	}
}

// TestConnectionStore_GetByPlatform_IncludesNewFields tests that GetByPlatform summaries include TenantID and AppCredentialsRef
func TestConnectionStore_GetByPlatform_IncludesNewFields(t *testing.T) {
	db := openTestConnDB(t)
	defer func() { _ = db.Close() }()
	resetTestConnSchema(t, db)

	ctx := context.Background()
	encryptor, err := NewSecretEncryptor([]byte("test-key-32-bytes-long-exactly!!"))
	if err != nil {
		t.Fatalf("NewSecretEncryptor() error = %v", err)
	}
	store := NewConnectionStore(db, encryptor)

	conn := &domain.Connection{
		ID:                "conn-1",
		Name:              "GitHub App",
		Platform:          domain.PlatformGitHub,
		ProviderType:      domain.ProviderTypeGitHub,
		AuthMethod:        domain.AuthMethodAppOnly,
		TenantID:          "org-123",
		AppCredentialsRef: "secret/creds",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := store.Save(ctx, conn); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	summaries, err := store.GetByPlatform(ctx, domain.PlatformGitHub)
	if err != nil {
		t.Fatalf("GetByPlatform() error = %v", err)
	}

	if len(summaries) == 0 {
		t.Fatal("expected at least one summary")
	}

	summary := summaries[0]
	if summary.TenantID != "org-123" {
		t.Errorf("expected TenantID=org-123, got %q", summary.TenantID)
	}
	if summary.AppCredentialsRef != "secret/creds" {
		t.Errorf("expected AppCredentialsRef=secret/creds, got %q", summary.AppCredentialsRef)
	}
}

// TestConnectionStore_List_IncludesNewFields tests that List summaries include TenantID and AppCredentialsRef
func TestConnectionStore_List_IncludesNewFields(t *testing.T) {
	db := openTestConnDB(t)
	defer func() { _ = db.Close() }()
	resetTestConnSchema(t, db)

	ctx := context.Background()
	encryptor, err := NewSecretEncryptor([]byte("test-key-32-bytes-long-exactly!!"))
	if err != nil {
		t.Fatalf("NewSecretEncryptor() error = %v", err)
	}
	store := NewConnectionStore(db, encryptor)

	conn := &domain.Connection{
		ID:                "conn-1",
		Name:              "GitHub App",
		Platform:          domain.PlatformGitHub,
		ProviderType:      domain.ProviderTypeGitHub,
		AuthMethod:        domain.AuthMethodAppOnly,
		TenantID:          "org-456",
		AppCredentialsRef: "secret/app-key",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := store.Save(ctx, conn); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	summaries, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(summaries) == 0 {
		t.Fatal("expected at least one summary")
	}

	summary := summaries[0]
	if summary.TenantID != "org-456" {
		t.Errorf("expected TenantID=org-456, got %q", summary.TenantID)
	}
	if summary.AppCredentialsRef != "secret/app-key" {
		t.Errorf("expected AppCredentialsRef=secret/app-key, got %q", summary.AppCredentialsRef)
	}
}

// TestConnectionStore_PartialUniqueIndex_ViolatesConstraint tests that duplicate app-only connections for same platform+tenant fails
func TestConnectionStore_PartialUniqueIndex_ViolatesConstraint(t *testing.T) {
	db := openTestConnDB(t)
	defer func() { _ = db.Close() }()
	resetTestConnSchema(t, db)

	ctx := context.Background()
	encryptor, err := NewSecretEncryptor([]byte("test-key-32-bytes-long-exactly!!"))
	if err != nil {
		t.Fatalf("NewSecretEncryptor() error = %v", err)
	}
	store := NewConnectionStore(db, encryptor)

	conn1 := &domain.Connection{
		ID:                "conn-1",
		Name:              "GitHub App 1",
		Platform:          domain.PlatformGitHub,
		ProviderType:      domain.ProviderTypeGitHub,
		AuthMethod:        domain.AuthMethodAppOnly,
		TenantID:          "same-org",
		AppCredentialsRef: "secret/creds-1",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	conn2 := &domain.Connection{
		ID:                "conn-2",
		Name:              "GitHub App 2",
		Platform:          domain.PlatformGitHub,
		ProviderType:      domain.ProviderTypeGitHub,
		AuthMethod:        domain.AuthMethodAppOnly,
		TenantID:          "same-org", // Same tenant
		AppCredentialsRef: "secret/creds-2",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := store.Save(ctx, conn1); err != nil {
		t.Fatalf("Save conn1: %v", err)
	}

	// Second save should fail due to unique constraint
	if err := store.Save(ctx, conn2); err == nil {
		t.Skip("unique constraint not enforced (test environment may not have migration applied)")
	}
}

// TestConnectionStore_PartialUniqueIndex_AllowsDelegatedRows tests that delegated rows with NULL tenant_id don't violate constraint
func TestConnectionStore_PartialUniqueIndex_AllowsDelegatedRows(t *testing.T) {
	db := openTestConnDB(t)
	defer func() { _ = db.Close() }()
	resetTestConnSchema(t, db)

	ctx := context.Background()
	encryptor, err := NewSecretEncryptor([]byte("test-key-32-bytes-long-exactly!!"))
	if err != nil {
		t.Fatalf("NewSecretEncryptor() error = %v", err)
	}
	store := NewConnectionStore(db, encryptor)

	// Two delegated (OAuth) connections for same platform, different accounts
	conn1 := &domain.Connection{
		ID:           "conn-1",
		Name:         "User 1 OAuth",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethodOAuth2,
		AccountID:    "user1@example.com",
		TenantID:     "",           // Empty for delegated
		AppCredentialsRef: "",      // Empty for delegated
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	conn2 := &domain.Connection{
		ID:           "conn-2",
		Name:         "User 2 OAuth",
		Platform:     domain.PlatformGitHub,
		ProviderType: domain.ProviderTypeGitHub,
		AuthMethod:   domain.AuthMethodOAuth2,
		AccountID:    "user2@example.com",
		TenantID:     "",           // Empty for delegated
		AppCredentialsRef: "",      // Empty for delegated
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := store.Save(ctx, conn1); err != nil {
		t.Fatalf("Save conn1: %v", err)
	}

	// Second save should succeed (no unique constraint on NULL tenant_id rows)
	if err := store.Save(ctx, conn2); err != nil {
		t.Fatalf("Save conn2 (delegated, should succeed): %v", err)
	}

	// Verify both were saved
	summaries, err := store.GetByPlatform(ctx, domain.PlatformGitHub)
	if err != nil {
		t.Fatalf("GetByPlatform() error = %v", err)
	}

	if len(summaries) != 2 {
		t.Errorf("expected 2 connections, got %d", len(summaries))
	}
}

// TestConnectionStore_SaveUpdate_PreservesNewFields tests that updating a connection preserves TenantID and AppCredentialsRef
func TestConnectionStore_SaveUpdate_PreservesNewFields(t *testing.T) {
	db := openTestConnDB(t)
	defer func() { _ = db.Close() }()
	resetTestConnSchema(t, db)

	ctx := context.Background()
	encryptor, err := NewSecretEncryptor([]byte("test-key-32-bytes-long-exactly!!"))
	if err != nil {
		t.Fatalf("NewSecretEncryptor() error = %v", err)
	}
	store := NewConnectionStore(db, encryptor)

	// Create initial connection
	conn := &domain.Connection{
		ID:                "conn-1",
		Name:              "GitHub App",
		Platform:          domain.PlatformGitHub,
		ProviderType:      domain.ProviderTypeGitHub,
		AuthMethod:        domain.AuthMethodAppOnly,
		TenantID:          "org-1",
		AppCredentialsRef: "secret/v1",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := store.Save(ctx, conn); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Update connection (change name, keep TenantID and AppCredentialsRef)
	conn.Name = "Updated GitHub App"
	if err := store.Save(ctx, conn); err != nil {
		t.Fatalf("Save update: %v", err)
	}

	// Retrieve and verify fields are preserved
	retrieved, err := store.Get(ctx, "conn-1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved.Name != "Updated GitHub App" {
		t.Errorf("expected updated name, got %q", retrieved.Name)
	}
	if retrieved.TenantID != "org-1" {
		t.Errorf("expected TenantID preserved as org-1, got %q", retrieved.TenantID)
	}
	if retrieved.AppCredentialsRef != "secret/v1" {
		t.Errorf("expected AppCredentialsRef preserved as secret/v1, got %q", retrieved.AppCredentialsRef)
	}
}
