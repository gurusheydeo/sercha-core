package driven

import (
	"context"

	"github.com/sercha-oss/sercha-core/internal/core/domain"
)

// ScopeContainerResolver lets a deployment override how the sync
// orchestrator discovers what to iterate for a source. The default path
// (used when no resolver is registered, or when the resolver returns
// (nil, nil)) iterates source.Containers as set on the Source row;
// resolvers can compute the container list from a richer side store
// when a connector's discovery shape doesn't fit the static
// source.Containers model.
//
// One resolver is registered per ProviderType via the orchestrator
// config. The orchestrator calls the resolver before each sync run
// and uses its result verbatim — order is preserved, duplicates are
// the resolver's responsibility to elide.
//
// Returning (nil, nil) is a "skip override" sentinel — the
// orchestrator falls through to source.Containers. Returning an empty
// non-nil slice means "no containers to sync this run", which the
// orchestrator treats as a successful no-op.
type ScopeContainerResolver interface {
	// ResolveContainers returns the container IDs the orchestrator
	// should iterate for source. The orchestrator calls connector.Build
	// once per returned ID and runs the standard per-container sync
	// loop unchanged — IDs are opaque strings the connector decodes.
	//
	// Returning a non-nil error short-circuits the sync run; the
	// orchestrator does NOT fall through to source.Containers in that
	// case, because an error here typically indicates the resolver's
	// backing store is unreachable and an unscoped fallback would
	// silently sync the wrong set.
	ResolveContainers(ctx context.Context, source *domain.Source) ([]string, error)
}

// ScopeContainerResolverRegistry dispatches to the right resolver by
// ProviderType. Optional on the orchestrator — when nil the
// orchestrator always uses source.Containers.
//
// Implementations are expected to be lock-free for the read path; the
// registry is mutated only at startup wiring time.
type ScopeContainerResolverRegistry interface {
	// Get returns the resolver for the source's ProviderType, or
	// (nil, false) when none is registered. The orchestrator falls
	// through to source.Containers on the false branch.
	Get(providerType domain.ProviderType) (ScopeContainerResolver, bool)
}
