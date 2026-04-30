package connectors

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestSharedTransport_SameProviderReturnsSameInstance verifies that two calls
// with the same provider name return the exact same *http.Transport pointer.
func TestSharedTransport_SameProviderReturnsSameInstance(t *testing.T) {
	// Use a unique test provider key to avoid interfering with other tests
	provider := "test-provider-same-instance"

	t1 := SharedTransport(provider)
	t2 := SharedTransport(provider)

	if t1 != t2 {
		t.Error("expected same *http.Transport instance for same provider")
	}
}

// TestSharedTransport_DifferentProvidersReturnDifferentInstances verifies that
// different provider names return different *http.Transport instances.
func TestSharedTransport_DifferentProvidersReturnDifferentInstances(t *testing.T) {
	// Use unique test provider keys
	providerA := "test-provider-a"
	providerB := "test-provider-b"

	tA := SharedTransport(providerA)
	tB := SharedTransport(providerB)

	if tA == tB {
		t.Error("expected different *http.Transport instances for different providers")
	}
}

// TestSharedTransport_ConcurrentFirstCall verifies that when 32 goroutines
// concurrently call SharedTransport for the same provider (first time),
// they all converge on the same instance.
func TestSharedTransport_ConcurrentFirstCall(t *testing.T) {
	// Use a unique provider key to ensure cold start
	provider := "test-provider-concurrent"

	const goroutines = 32
	results := make([]*http.Transport, goroutines)
	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for all goroutines to be ready
			results[idx] = SharedTransport(provider)
		}(i)
	}

	close(start) // Signal all goroutines to start simultaneously
	wg.Wait()

	// Verify all goroutines got the same instance
	for i := 1; i < goroutines; i++ {
		if results[i] != results[0] {
			t.Errorf("goroutine %d returned different instance than goroutine 0", i)
		}
	}
}

// TestSharedTransport_MicrosoftTuning verifies that the Microsoft provider
// transport has the expected tuning parameters.
func TestSharedTransport_MicrosoftTuning(t *testing.T) {
	transport := SharedTransport("microsoft")

	if transport.MaxIdleConnsPerHost != 8 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 8", transport.MaxIdleConnsPerHost)
	}

	if transport.MaxIdleConns != 32 {
		t.Errorf("MaxIdleConns = %d, want 32", transport.MaxIdleConns)
	}

	expectedTimeout := 90 * time.Second
	if transport.IdleConnTimeout != expectedTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", transport.IdleConnTimeout, expectedTimeout)
	}

	expectedTLSTimeout := 10 * time.Second
	if transport.TLSHandshakeTimeout != expectedTLSTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", transport.TLSHandshakeTimeout, expectedTLSTimeout)
	}

	expectedContinueTimeout := 1 * time.Second
	if transport.ExpectContinueTimeout != expectedContinueTimeout {
		t.Errorf("ExpectContinueTimeout = %v, want %v", transport.ExpectContinueTimeout, expectedContinueTimeout)
	}
}

// TestSharedTransport_UnknownProviderFallback verifies that an unknown provider
// receives a cloned DefaultTransport with no custom tuning. SharedTransport
// always returns a non-nil *http.Transport.
func TestSharedTransport_UnknownProviderFallback(t *testing.T) {
	transport := SharedTransport("unknown-provider-xyz")

	// Unknown providers should not have microsoft-specific tuning
	// (they'll have default Go values after Clone).
	if transport.MaxIdleConnsPerHost == 8 {
		t.Error("unknown provider should not have Microsoft tuning (MaxIdleConnsPerHost=8)")
	}
}
