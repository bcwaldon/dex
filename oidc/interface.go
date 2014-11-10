package oidc

import (
	"net/http"

	"github.com/coreos-inc/auth/oauth2"
)

type LoginFunc func(w http.ResponseWriter, acr oauth2.AuthCodeRequest, ident Identity)
