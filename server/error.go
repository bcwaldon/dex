package server

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/pkg/log"
)

const (
	errorInvalidRequest = "invalid_request"
	errorServerError    = "server_error"
)

type apiError struct {
	Type        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *apiError) Error() string {
	return e.Type
}

func newAPIError(typ, desc string) *apiError {
	return &apiError{Type: typ, Description: desc}
}

func writeAPIError(w http.ResponseWriter, code int, err error) {
	aerr, ok := err.(*apiError)
	if !ok {
		aerr = newAPIError(errorServerError, "")
	}
	if aerr.Type == "" {
		aerr.Type = errorServerError
	}
	if code == 0 {
		code = http.StatusInternalServerError
	}
	writeResponse(w, code, aerr)
}

func writeTokenError(w http.ResponseWriter, err error, state string) {
	oerr, ok := err.(*oauth2.Error)
	if !ok {
		oerr = oauth2.NewError(oauth2.ErrorServerError)
	}
	oerr.State = state

	var status int
	switch oerr.Type {
	case oauth2.ErrorInvalidClient:
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", "Basic")
	default:
		status = http.StatusBadRequest
	}

	b, err := json.Marshal(oerr)
	if err != nil {
		log.Errorf("Failed marshaling OAuth2 error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

func writeAuthError(w http.ResponseWriter, err error, state string) {
	oerr, ok := err.(*oauth2.Error)
	if !ok {
		oerr = oauth2.NewError(oauth2.ErrorServerError)
	}
	oerr.State = state

	b, err := json.Marshal(oerr)
	if err != nil {
		log.Errorf("Failed marshaling OAuth2 error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(b)
}

func redirectAuthError(w http.ResponseWriter, err error, state string, redirectURL url.URL) {
	oerr, ok := err.(*oauth2.Error)
	if !ok {
		oerr = oauth2.NewError(oauth2.ErrorServerError)
	}

	q := redirectURL.Query()
	q.Set("error", oerr.Type)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()

	w.Header().Set("Location", redirectURL.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
}
