package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServer_RegisterRoute_ServesAfterRegistration(t *testing.T) {
	s := &Server{router: http.NewServeMux()}

	var called bool
	s.RegisterRoute("GET /custom", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/custom", nil)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)

	if !called {
		t.Fatal("registered handler was not invoked")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Body.String(); got != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
}

func TestServer_RegisterRouteFunc_ServesAfterRegistration(t *testing.T) {
	s := &Server{router: http.NewServeMux()}

	var called bool
	s.RegisterRouteFunc("GET /funcvariant", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})

	req := httptest.NewRequest("GET", "/funcvariant", nil)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)

	if !called {
		t.Fatal("registered HandlerFunc was not invoked")
	}
	if rr.Code != http.StatusTeapot {
		t.Fatalf("expected 418, got %d", rr.Code)
	}
}

func TestServer_RegisterRoute_ConflictPanics(t *testing.T) {
	s := &Server{router: http.NewServeMux()}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	s.RegisterRoute("GET /dup", h)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate pattern registration")
		}
	}()
	s.RegisterRoute("GET /dup", h)
}

func TestServer_RegisterRoute_CallerMiddlewareWraps(t *testing.T) {
	s := &Server{router: http.NewServeMux()}

	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Wrapped", "yes")
			next.ServeHTTP(w, r)
		})
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	s.RegisterRoute("GET /wrapped", middleware(inner))

	req := httptest.NewRequest("GET", "/wrapped", nil)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Wrapped"); got != "yes" {
		t.Errorf("X-Wrapped header = %q, want %q — caller middleware did not run", got, "yes")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
