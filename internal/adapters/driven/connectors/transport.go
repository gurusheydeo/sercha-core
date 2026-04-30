// Package connectors provides process-level shared infrastructure for all
// external service connectors — token pooling, transport pooling, and the
// factory that composes them.
package connectors

import (
	"net/http"
	"sync"
	"time"
)

var (
	transportsMu sync.Mutex
	transports   = map[string]*http.Transport{}
)

// SharedTransport returns a process-singleton *http.Transport for the named
// provider. Subsequent calls for the same provider key return the exact same
// instance — keepalive connections and TLS sessions are pooled across every
// consumer of that provider (content fetch, permission fetch, group membership
// fetch, webhook receivers, etc.).
//
// The map is guarded by a plain Mutex rather than an RWMutex: the first-call
// path does an allocation, so write-lock semantics are correct; the read path
// after construction is essentially free either way.
//
// Tuning is per-provider via the internal newTransportFor helper. Unknown
// providers receive a cloned copy of http.DefaultTransport (same defaults,
// separate pool so their connections don't bleed into DefaultTransport).
//
// The returned transport is permanent for the lifetime of the process —
// callers MUST NOT close, modify, or replace it. There is no fd leak
// because connectors are registered once at startup and the set of
// providers is bounded.
func SharedTransport(provider string) *http.Transport {
	transportsMu.Lock()
	defer transportsMu.Unlock()
	if t, ok := transports[provider]; ok {
		return t
	}
	t := newTransportFor(provider)
	transports[provider] = t
	return t
}

// newTransportFor constructs a tuned *http.Transport for the given provider.
// It always starts from a Clone of http.DefaultTransport so that Go's default
// TLS, proxy, and dial settings are preserved.
func newTransportFor(provider string) *http.Transport {
	base := http.DefaultTransport.(*http.Transport).Clone()
	switch provider {
	case "microsoft":
		// Microsoft Graph rate-limits per-app per-host; 8 keepalive
		// connections per host avoids TLS handshake stack-up under
		// concurrent bursts (content fetch + permission observer in
		// parallel). 32 total idle conns gives headroom across the
		// graph.microsoft.com and login.microsoftonline.com hostnames.
		base.MaxIdleConns = 32
		base.MaxIdleConnsPerHost = 8
		base.IdleConnTimeout = 90 * time.Second
		base.TLSHandshakeTimeout = 10 * time.Second
		base.ExpectContinueTimeout = 1 * time.Second
	}
	return base
}
