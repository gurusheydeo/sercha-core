package mocks

import (
	"context"
	"testing"
	"time"

	"github.com/sercha-oss/sercha-core/internal/core/domain"
)

// TestMockConnectionStore_SaveAndGetByTenantID tests Save and GetByTenantID via the mock
func TestMockConnectionStore_SaveAndGetByTenantID(t *testing.T) {
	mock := NewMockConnectionStore()
	ctx := context.Background()

	conn := &domain.Connection{
		ID:                "app-conn-1",
		Name:              "App Connection",
		Platform:          domain.PlatformGitHub,
		ProviderType:      domain.ProviderTypeGitHub,
		AuthMethod:        domain.AuthMethodAppOnly,
		TenantID:          "my-org",
		AppCredentialsRef: "secret/creds",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	// Save the connection
	if err := mock.Save(ctx, conn); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Retrieve by TenantID
	retrieved, err := mock.GetByTenantID(ctx, domain.PlatformGitHub, "my-org")
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

	if retrieved.AppCredentialsRef != "secret/creds" {
		t.Errorf("expected AppCredentialsRef=secret/creds, got %q", retrieved.AppCredentialsRef)
	}
}

// TestMockConnectionStore_GetByTenantID_NotFound tests that GetByTenantID returns nil when not found
func TestMockConnectionStore_GetByTenantID_NotFound(t *testing.T) {
	mock := NewMockConnectionStore()
	ctx := context.Background()

	retrieved, err := mock.GetByTenantID(ctx, domain.PlatformGitHub, "nonexistent")
	if err != nil {
		t.Fatalf("GetByTenantID() error = %v", err)
	}

	if retrieved != nil {
		t.Error("expected nil for nonexistent tenant")
	}
}

// TestMockConnectionStore_Reset_ClearsByTenant tests that Reset clears the byTenant map
func TestMockConnectionStore_Reset_ClearsByTenant(t *testing.T) {
	mock := NewMockConnectionStore()
	ctx := context.Background()

	conn := &domain.Connection{
		ID:       "conn-1",
		Platform: domain.PlatformGitHub,
		TenantID: "org-1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := mock.Save(ctx, conn); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify it's there
	if count := mock.Count(); count != 1 {
		t.Errorf("expected 1 connection, got %d", count)
	}

	// Reset
	mock.Reset()

	// Verify it's gone
	if count := mock.Count(); count != 0 {
		t.Errorf("expected 0 connections after Reset, got %d", count)
	}

	// Verify GetByTenantID returns nil
	retrieved, err := mock.GetByTenantID(ctx, domain.PlatformGitHub, "org-1")
	if err != nil {
		t.Fatalf("GetByTenantID() after Reset error = %v", err)
	}

	if retrieved != nil {
		t.Error("expected nil for connection after Reset")
	}
}

// TestMockConnectionStore_SaveAndDelete_CleansByTenant tests that Delete cleans up the byTenant map
func TestMockConnectionStore_SaveAndDelete_CleansByTenant(t *testing.T) {
	mock := NewMockConnectionStore()
	ctx := context.Background()

	conn := &domain.Connection{
		ID:       "conn-1",
		Platform: domain.PlatformGitHub,
		TenantID: "org-1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := mock.Save(ctx, conn); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify it's there
	retrieved, err := mock.GetByTenantID(ctx, domain.PlatformGitHub, "org-1")
	if err != nil {
		t.Fatalf("GetByTenantID() before Delete error = %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected connection to exist before Delete")
	}

	// Delete
	if err := mock.Delete(ctx, "conn-1"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify it's gone from byTenant
	retrieved, err = mock.GetByTenantID(ctx, domain.PlatformGitHub, "org-1")
	if err != nil {
		t.Fatalf("GetByTenantID() after Delete error = %v", err)
	}

	if retrieved != nil {
		t.Error("expected nil for deleted connection")
	}
}
