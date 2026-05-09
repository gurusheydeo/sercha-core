package services

import (
	"context"
	"errors"
	"testing"

	"github.com/sercha-oss/sercha-core/internal/core/domain"
	"github.com/sercha-oss/sercha-core/internal/core/ports/driven"
)

// fakeScopeResolver records every call + can return canned containers/error.
type fakeScopeResolver struct {
	containers []string
	err        error
	called     int
	gotSource  *domain.Source
}

func (f *fakeScopeResolver) ResolveContainers(ctx context.Context, source *domain.Source) ([]string, error) {
	f.called++
	f.gotSource = source
	return f.containers, f.err
}

// fakeRegistry returns a single resolver for one ProviderType.
type fakeRegistry struct {
	resolver driven.ScopeContainerResolver
	pt       domain.ProviderType
}

func (f *fakeRegistry) Get(pt domain.ProviderType) (driven.ScopeContainerResolver, bool) {
	if pt == f.pt && f.resolver != nil {
		return f.resolver, true
	}
	return nil, false
}

// fakeEncoding decodes "type:external_id" pairs into ScopeRefs.
type fakeColonEncoding struct{}

func (fakeColonEncoding) Decode(containerID string) ScopeRef {
	for i := 0; i < len(containerID); i++ {
		if containerID[i] == ':' {
			return ScopeRef{Type: containerID[:i], ExternalID: containerID[i+1:]}
		}
	}
	return ScopeRef{ExternalID: containerID}
}

// instrumentFactory wraps the test factory to capture every Create call's
// containerID so the resolver tests can assert on iteration without
// reaching into the shared MockConnector.
type instrumentFactory struct {
	*mockConnectorFactory
	gotContainerIDs []string
}

func newInstrumentFactory(base *mockConnectorFactory) *instrumentFactory {
	return &instrumentFactory{mockConnectorFactory: base}
}

func (i *instrumentFactory) Create(ctx context.Context, source *domain.Source, containerID string) (driven.Connector, error) {
	i.gotContainerIDs = append(i.gotContainerIDs, containerID)
	return i.mockConnectorFactory.Create(ctx, source, containerID)
}

func TestSyncSource_ResolverReturnsNil_FallsBackToSourceContainers(t *testing.T) {
	o, srcStore, _, _, _, cf := createTestSyncOrchestrator(t)
	resolver := &fakeScopeResolver{containers: nil} // explicit nil → fall-through
	o.scopeResolvers = &fakeRegistry{resolver: resolver, pt: "github"}

	instr := newInstrumentFactory(cf)
	o.connectorFactory = instr

	source := &domain.Source{
		ID: "s1", Name: "S", ProviderType: "github", Enabled: true,
		Containers: []domain.Container{{ID: "c-from-source"}},
	}
	if err := srcStore.Save(context.Background(), source); err != nil {
		t.Fatalf("save source: %v", err)
	}

	_, err := o.SyncSource(context.Background(), "s1")
	if err != nil {
		t.Fatalf("SyncSource: %v", err)
	}
	if resolver.called != 1 {
		t.Errorf("resolver called %d, want 1", resolver.called)
	}
	if len(instr.gotContainerIDs) == 0 || instr.gotContainerIDs[0] != "c-from-source" {
		t.Errorf("Create container IDs = %v, want first = c-from-source", instr.gotContainerIDs)
	}
}

func TestSyncSource_ResolverEmptyNonNil_NoContainersIterated(t *testing.T) {
	o, srcStore, _, _, _, cf := createTestSyncOrchestrator(t)
	resolver := &fakeScopeResolver{containers: []string{}} // empty non-nil → no work
	o.scopeResolvers = &fakeRegistry{resolver: resolver, pt: "github"}

	instr := newInstrumentFactory(cf)
	o.connectorFactory = instr

	source := &domain.Source{
		ID: "s1", Name: "S", ProviderType: "github", Enabled: true,
		Containers: []domain.Container{{ID: "c-should-be-ignored"}},
	}
	_ = srcStore.Save(context.Background(), source)

	_, err := o.SyncSource(context.Background(), "s1")
	if err != nil {
		t.Fatalf("SyncSource: %v", err)
	}
	if len(instr.gotContainerIDs) != 0 {
		t.Errorf("Create called for %v containers, want 0", instr.gotContainerIDs)
	}
}

func TestSyncSource_ResolverError_ShortCircuits(t *testing.T) {
	o, srcStore, _, _, _, _ := createTestSyncOrchestrator(t)
	resolver := &fakeScopeResolver{err: errors.New("backing store down")}
	o.scopeResolvers = &fakeRegistry{resolver: resolver, pt: "github"}

	source := &domain.Source{
		ID: "s1", Name: "S", ProviderType: "github", Enabled: true,
		Containers: []domain.Container{{ID: "c-from-source"}},
	}
	_ = srcStore.Save(context.Background(), source)

	_, err := o.SyncSource(context.Background(), "s1")
	if err == nil {
		t.Fatalf("SyncSource succeeded; want error from resolver")
	}
	if !errors.Is(err, errors.Unwrap(err)) || err.Error() == "" {
		t.Errorf("err = %v; want non-empty wrapping", err)
	}
}

func TestSyncSource_NoResolverRegistered_FallsBackToSourceContainers(t *testing.T) {
	o, srcStore, _, _, _, cf := createTestSyncOrchestrator(t)
	// Registry exists but doesn't have an entry for this provider.
	o.scopeResolvers = &fakeRegistry{resolver: nil, pt: "other-provider"}

	instr := newInstrumentFactory(cf)
	o.connectorFactory = instr

	source := &domain.Source{
		ID: "s1", Name: "S", ProviderType: "github", Enabled: true,
		Containers: []domain.Container{{ID: "c-from-source"}},
	}
	_ = srcStore.Save(context.Background(), source)

	_, err := o.SyncSource(context.Background(), "s1")
	if err != nil {
		t.Fatalf("SyncSource: %v", err)
	}
	if len(instr.gotContainerIDs) == 0 || instr.gotContainerIDs[0] != "c-from-source" {
		t.Errorf("Create container IDs = %v, want first = c-from-source", instr.gotContainerIDs)
	}
}

func TestSyncSource_ResolverContainers_ScopeRefThreadedOnContext(t *testing.T) {
	o, srcStore, _, _, _, cf := createTestSyncOrchestrator(t)
	o.scopeResolvers = &fakeRegistry{
		resolver: &fakeScopeResolver{containers: []string{"user:alice@co.com"}},
		pt:       "github",
	}
	o.scopeEncoding = fakeColonEncoding{}

	// Capture the ScopeRef seen by the connector via FetchChanges.
	var seen ScopeRef
	cf.connector.FetchChangesFn = func(ctx context.Context, _ *domain.Source, _ string) ([]*domain.Change, string, error) {
		seen = ScopeRefFromContext(ctx)
		return nil, "", nil
	}

	source := &domain.Source{
		ID: "s1", Name: "S", ProviderType: "github", Enabled: true,
	}
	_ = srcStore.Save(context.Background(), source)

	_, err := o.SyncSource(context.Background(), "s1")
	if err != nil {
		t.Fatalf("SyncSource: %v", err)
	}

	want := ScopeRef{Type: "user", ExternalID: "alice@co.com"}
	if seen != want {
		t.Errorf("ScopeRef seen by connector = %+v, want %+v", seen, want)
	}
}
