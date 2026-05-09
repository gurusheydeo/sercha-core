package services

import (
	"context"
	"testing"
)

func TestScopeRef_IsZero(t *testing.T) {
	cases := []struct {
		ref  ScopeRef
		want bool
	}{
		{ScopeRef{}, true},
		{ScopeRef{Type: "user"}, false},
		{ScopeRef{ExternalID: "x"}, false},
		{ScopeRef{Type: "user", ExternalID: "x"}, false},
	}
	for _, c := range cases {
		if got := c.ref.IsZero(); got != c.want {
			t.Errorf("ScopeRef(%+v).IsZero() = %v, want %v", c.ref, got, c.want)
		}
	}
}

func TestScopeRefFromContext_AbsentReturnsZero(t *testing.T) {
	got := ScopeRefFromContext(context.Background())
	if !got.IsZero() {
		t.Errorf("expected zero ScopeRef, got %+v", got)
	}
}

func TestWithScopeRef_RoundTrip(t *testing.T) {
	ref := ScopeRef{Type: "site", ExternalID: "site-eng"}
	ctx := WithScopeRef(context.Background(), ref)
	got := ScopeRefFromContext(ctx)
	if got != ref {
		t.Errorf("got %+v, want %+v", got, ref)
	}
}

func TestWithScopeRef_NestedOverrides(t *testing.T) {
	outer := ScopeRef{Type: "user", ExternalID: "alice"}
	inner := ScopeRef{Type: "group", ExternalID: "marketing"}

	ctx := WithScopeRef(context.Background(), outer)
	ctx2 := WithScopeRef(ctx, inner)

	if got := ScopeRefFromContext(ctx2); got != inner {
		t.Errorf("inner = %+v, want %+v", got, inner)
	}
	// Outer unchanged.
	if got := ScopeRefFromContext(ctx); got != outer {
		t.Errorf("outer = %+v, want %+v", got, outer)
	}
}
