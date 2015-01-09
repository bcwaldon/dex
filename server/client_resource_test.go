package server

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/schema"
)

func makeBody(s string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(s))
}

func TestCreateInvalidRequest(t *testing.T) {
	u := &url.URL{Scheme: "http", Host: "example.com", Path: "clients"}
	h := http.Header{"Content-Type": []string{"application/json"}}
	repo := NewClientIdentityRepo(nil)
	res := &clientResource{repo: repo}
	tests := []struct {
		req      *http.Request
		wantCode int
		wantBody string
	}{
		// invalid content-type
		{
			req:      &http.Request{Method: "POST", URL: u, Header: http.Header{"Content-Type": []string{"application/xml"}}},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error":"invalid_request","error_description":"unsupported content-type"}`,
		},
		// invalid method
		{
			req:      &http.Request{Method: "DELETE", URL: u, Header: h},
			wantCode: http.StatusMethodNotAllowed,
			wantBody: `{"error":"invalid_request","error_description":"HTTP DELETE method not supported for this resource"}`,
		},
		// invalid method
		{
			req:      &http.Request{Method: "PUT", URL: u, Header: h},
			wantCode: http.StatusMethodNotAllowed,
			wantBody: `{"error":"invalid_request","error_description":"HTTP PUT method not supported for this resource"}`,
		},
		// invalid method
		{
			req:      &http.Request{Method: "HEAD", URL: u, Header: h},
			wantCode: http.StatusMethodNotAllowed,
			wantBody: `{"error":"invalid_request","error_description":"HTTP HEAD method not supported for this resource"}`,
		},
		// unserializable body
		{
			req:      &http.Request{Method: "POST", URL: u, Header: h, Body: makeBody("asdf")},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error":"invalid_request","error_description":"unable to decode request body"}`,
		},
		// empty body
		{
			req:      &http.Request{Method: "POST", URL: u, Header: h, Body: makeBody("")},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error":"invalid_request","error_description":"unable to decode request body"}`,
		},
		// missing url field
		{
			req:      &http.Request{Method: "POST", URL: u, Header: h, Body: makeBody(`{"id":"foo"}`)},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error":"invalid_client_metadata","error_description":"missing or invalid field: redirectURIs"}`,
		},
		// empty url array
		{
			req:      &http.Request{Method: "POST", URL: u, Header: h, Body: makeBody(`{"redirectURIs":[]}`)},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error":"invalid_client_metadata","error_description":"missing or invalid field: redirectURIs"}`,
		},
		// array with empty string
		{
			req:      &http.Request{Method: "POST", URL: u, Header: h, Body: makeBody(`{"redirectURIs":[""]}`)},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error":"invalid_client_metadata","error_description":"missing or invalid field: redirectURIs"}`,
		},
		// uri missing scheme
		{
			req:      &http.Request{Method: "POST", URL: u, Header: h, Body: makeBody(`{"redirectURIs":["asdf.com"]}`)},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error":"invalid_client_metadata","error_description":"missing or invalid field: redirectURIs"}`,
		},
		// uri missing host
		{
			req:      &http.Request{Method: "POST", URL: u, Header: h, Body: makeBody(`{"redirectURIs":["http://"]}`)},
			wantCode: http.StatusBadRequest,
			wantBody: `{"error":"invalid_client_metadata","error_description":"missing or invalid field: redirectURIs"}`,
		},
	}

	for i, tt := range tests {
		w := httptest.NewRecorder()
		res.ServeHTTP(w, tt.req)

		if w.Code != tt.wantCode {
			t.Errorf("case %d: invalid response code, want=%d, got=%d", i, tt.wantCode, w.Code)
		}

		gotBody := w.Body.String()
		if gotBody != tt.wantBody {
			t.Errorf("case %d: invalid response body, want=%s, got=%s", i, tt.wantBody, gotBody)
		}
	}
}

func TestCreate(t *testing.T) {
	repo := NewClientIdentityRepo(nil)
	res := &clientResource{repo: repo}
	tests := [][]string{
		[]string{"http://example.com"},
		[]string{"https://example.com"},
		[]string{"http://example.com/foo"},
		[]string{"http://example.com/bar", "http://example.com/foo"},
	}
	endpoint := "http://example.com/clients"

	for i, tt := range tests {
		body := strings.NewReader(fmt.Sprintf(`{"redirectURIs":["%s"]}`, strings.Join(tt, `","`)))
		r, err := http.NewRequest("POST", endpoint, body)
		if err != nil {
			t.Fatalf("Failed creating http.Request: %v", err)
		}
		r.Header.Set("content-type", "application/json")
		w := httptest.NewRecorder()
		res.ServeHTTP(w, r)

		if w.Code != http.StatusCreated {
			t.Errorf("case %d: invalid response code, want=%d, got=%d", i, http.StatusCreated, w.Code)
		}

		var client schema.ClientWithSecret
		if err := json.Unmarshal(w.Body.Bytes(), &client); err != nil {
			t.Errorf("case %d: unexpected error=%v", i, err)
		}
		if len(client.RedirectURIs) != 1 {
			t.Errorf("case %d: unexpected number of redirect URIs, want=1, got=%d", i, len(client.RedirectURIs))
		}

		gotURL := client.RedirectURIs[0]
		for i, u := range tt {
			if u == gotURL {
				break
			}
			if i == len(tt)-1 {
				t.Errorf("case %d: unexpected client URI, want one of=%v, got=%s", i, tt, gotURL)
			}
		}

		if client.Id == "" {
			t.Errorf("case %d: empty client ID in response", i)
		}

		if client.Secret == "" {
			t.Errorf("case %d: empty client secret in response", i)
		}

		wantLoc := fmt.Sprintf("%s/%s", endpoint, client.Id)
		gotLoc := w.Header().Get("Location")
		if gotLoc != wantLoc {
			t.Errorf("case %d: invalid location header, want=%v, got=%v", i, wantLoc, gotLoc)
		}
	}
}

func TestList(t *testing.T) {
	tests := []struct {
		cs       []oidc.ClientIdentity
		wantBody string
	}{
		// empty repo
		{
			cs:       nil,
			wantBody: `{}`,
		},
		// single client
		{
			cs: []oidc.ClientIdentity{
				oidc.ClientIdentity{
					Credentials: oidc.ClientCredentials{ID: "foo", Secret: "bar"},
					Metadata: oidc.ClientMetadata{
						RedirectURL: url.URL{Scheme: "http", Host: "example.com"},
					},
				},
			},
			wantBody: `{"clients":[{"id":"foo","redirectURIs":["http://example.com"]}]}`,
		},
		// multi client
		{
			cs: []oidc.ClientIdentity{
				oidc.ClientIdentity{
					Credentials: oidc.ClientCredentials{ID: "foo", Secret: "bar"},
					Metadata: oidc.ClientMetadata{
						RedirectURL: url.URL{Scheme: "http", Host: "example.com"},
					},
				},
				oidc.ClientIdentity{
					Credentials: oidc.ClientCredentials{ID: "biz", Secret: "bang"},
					Metadata: oidc.ClientMetadata{
						RedirectURL: url.URL{Scheme: "https", Host: "example.com", Path: "one/two/three"},
					},
				},
			},
			wantBody: `{"clients":[{"id":"foo","redirectURIs":["http://example.com"]},{"id":"biz","redirectURIs":["https://example.com/one/two/three"]}]}`,
		},
	}

	for i, tt := range tests {
		repo := NewClientIdentityRepo(tt.cs)
		res := &clientResource{repo: repo}

		r, err := http.NewRequest("GET", "http://example.com/clients", nil)
		if err != nil {
			t.Fatalf("Failed creating http.Request: %v", err)
		}
		w := httptest.NewRecorder()
		res.ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("case %d: invalid response code, want=%d, got=%d", i, http.StatusOK, w.Code)
		}

		gotBody := w.Body.String()
		if gotBody != tt.wantBody {
			t.Errorf("case %d: invalid response body, want=%s, got=%s", i, tt.wantBody, gotBody)
		}
	}
}
