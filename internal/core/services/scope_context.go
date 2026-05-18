package services

import "context"

// ScopeRef is a small, stable reference to whatever scope the
// orchestrator is currently fanning out for. The fields are opaque
// strings — the orchestrator doesn't interpret them, it only threads
// them onto the per-container context so observers and downstream
// adapters can read them back.
//
// A scope is, conceptually, the "named slice of upstream world this
// container iteration represents" — but the orchestrator's view of it
// is intentionally generic so connectors that don't have a scope
// concept (single-source GitHub, Notion) can leave the context value
// absent and observers see the empty zero-value.
type ScopeRef struct {
	// Type is a connector-defined category (e.g. "user", "site",
	// "group") or empty when the connector has no scope concept.
	Type string

	// ExternalID is the connector-defined identifier of the scope
	// inside its upstream world. Opaque to Core.
	ExternalID string
}

// IsZero reports whether the ScopeRef is the empty value — used by
// observers to skip scope-aware bookkeeping for sources whose
// connector doesn't set a scope.
func (s ScopeRef) IsZero() bool {
	return s.Type == "" && s.ExternalID == ""
}

// scopeRefCtxKey is the unexported context key that carries a ScopeRef
// across the orchestrator → connector → observer chain. Using an
// instance-typed unexported struct prevents collisions with other
// packages that might also stash values on the same context.
type scopeRefCtxKey struct{}

// WithScopeRef returns a child context carrying the given ScopeRef.
// The orchestrator calls this before invoking the connector for one
// container iteration, and observers reading the context see the same
// value through the call chain.
func WithScopeRef(ctx context.Context, ref ScopeRef) context.Context {
	return context.WithValue(ctx, scopeRefCtxKey{}, ref)
}

// ScopeRefFromContext returns the ScopeRef set via WithScopeRef. When
// no value has been attached, returns the empty ScopeRef — callers
// can use ScopeRef.IsZero to skip scope-specific work.
func ScopeRefFromContext(ctx context.Context) ScopeRef {
	v, _ := ctx.Value(scopeRefCtxKey{}).(ScopeRef)
	return v
}
