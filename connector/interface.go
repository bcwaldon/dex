package connector

import (
	"net/http"
)

type IDPConnector interface {
	DisplayType() string
	LoginURL(r *http.Request) string
	Register(mux *http.ServeMux)
}
