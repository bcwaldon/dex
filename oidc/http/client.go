package http

import (
	"fmt"
	"net/http"

	"github.com/coreos-inc/auth/oidc"
)

var (
	PathCallback = "/callback"
)

func NewClientCallbackHandlerFunc(c *oidc.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			writeError(w, http.StatusBadRequest, "code query param must be set")
			return
		}

		tok, err := c.ExchangeAuthCode(code)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unable to verify auth code with issuer: %v", err))
			return
		}

		w.Write([]byte(fmt.Sprintf("OK: %v", tok.Claims)))
	}
}
