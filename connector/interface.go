package connector

import (
	"net/http"

	"github.com/coreos-inc/auth/oidc"
)

type IDPConnector interface {
	DisplayType() string
	Identify(r *http.Request) (*oidc.Identity, error)
}
