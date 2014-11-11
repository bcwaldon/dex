package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleAuthFuncMethodNotAllowed(t *testing.T) {
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		hdlr := handleAuthFunc(nil, nil)
		req, err := http.NewRequest(m, "http://example.com", nil)
		if err != nil {
			t.Errorf("case %s: unable to create HTTP request: %v", m, err)
			continue
		}

		w := httptest.NewRecorder()
		hdlr.ServeHTTP(w, req)

		want := http.StatusMethodNotAllowed
		got := w.Code
		if want != got {
			t.Errorf("case %s: expected HTTP %d, got %d", m, want, got)
		}
	}
}

func TestHandleTokenFuncMethodNotAllowed(t *testing.T) {
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		hdlr := handleTokenFunc(nil, nil)
		req, err := http.NewRequest(m, "http://example.com", nil)
		if err != nil {
			t.Errorf("case %s: unable to create HTTP request: %v", m, err)
			continue
		}

		w := httptest.NewRecorder()
		hdlr.ServeHTTP(w, req)

		want := http.StatusMethodNotAllowed
		got := w.Code
		if want != got {
			t.Errorf("case %s: expected HTTP %d, got %d", m, want, got)
		}
	}
}
