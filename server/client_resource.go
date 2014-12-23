package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	phttp "github.com/coreos-inc/auth/pkg/http"
	"github.com/coreos-inc/auth/pkg/log"
	"github.com/coreos-inc/auth/schema"
)

type clientResource struct {
	repo ClientIdentityRepo
}

func registerClientResource(prefix string, mux *http.ServeMux, repo ClientIdentityRepo) {
	c := &clientResource{repo}
	p := path.Join(prefix, "clients")
	mux.Handle(p, c)
}

func (c *clientResource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		c.create(w, r)
	default:
		msg := fmt.Sprintf("HTTP %s method not supported for this resource", r.Method)
		writeAPIError(w, http.StatusMethodNotAllowed, newAPIError(errorInvalidRequest, msg))
	}
}

func (c *clientResource) create(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("content-type")
	if ct != "application/json" {
		log.Debugf("Unsupported request content-type: %v", ct)
		writeAPIError(w, http.StatusBadRequest, newAPIError(errorInvalidRequest, "unsupported content-type"))
		return
	}

	var sc schema.Client
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&sc)
	if err != nil {
		log.Debugf("Error decoding request body: %v", err)
		writeAPIError(w, http.StatusBadRequest, newAPIError(errorInvalidRequest, "unable to decode request body"))
		return
	}

	ci, err := schema.MapSchemaClientToClientIdentity(sc)
	if err != nil {
		log.Debugf("Invalid request data: %v", err)
		writeAPIError(w, http.StatusBadRequest, newAPIError(errorInvalidClientMetadata, "missing or invalid field: redirect_uris"))
		return
	}
	u := ci.Metadata.RedirectURL
	if u.Scheme == "" || u.Host == "" {
		writeAPIError(w, http.StatusBadRequest, newAPIError(errorInvalidClientMetadata, "missing or invalid field: redirect_uris"))
		return
	}

	creds, err := c.repo.New(ci.Metadata)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, newAPIError(errorInvalidClientMetadata, "missing or invalid field: redirect_uris"))
		return
	}
	ci.Credentials = *creds

	sc = schema.MapClientIdentityToSchemaClient(ci)
	w.Header().Add("Location", phttp.NewResourceLocation(r.URL, ci.Credentials.ID))
	writeResponseWithBody(w, http.StatusCreated, sc)
}
