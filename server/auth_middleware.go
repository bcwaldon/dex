package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos-inc/auth/pkg/log"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/go-oidc/oidc"
)

type clientTokenMiddleware struct {
	issuerURL string
	ciRepo    ClientIdentityRepo
	keysFunc  func() ([]key.PublicKey, error)
	next      http.Handler
}

func (c *clientTokenMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	respondError := func() {
		writeAPIError(w, http.StatusUnauthorized, newAPIError(errorAccessDenied, "missing or invalid token"))
	}

	if c.keysFunc == nil {
		log.Errorf("Misconfigured clientTokenMiddleware, keysFunc is not set")
		respondError()
		return
	}

	if c.ciRepo == nil {
		log.Errorf("Misconfigured clientTokenMiddleware, ClientIdentityRepo is not set")
		respondError()
		return
	}

	jwt, err := oidc.ParseTokenFromRequest(r)
	if err != nil {
		log.Errorf("Failed to parse JWT from request: %v", err)
		respondError()
		return
	}

	keys, err := c.keysFunc()
	if err != nil {
		log.Errorf("Failed to get keys: %v", err)
		writeAPIError(w, http.StatusUnauthorized, newAPIError(errorAccessDenied, ""))
		respondError()
		return
	} else if len(keys) == 0 {
		log.Error("No keys available for verification in client token middleware")
		writeAPIError(w, http.StatusUnauthorized, newAPIError(errorAccessDenied, ""))
		respondError()
		return
	}

	ok, err := oidc.VerifySignature(jwt, keys)
	if err != nil {
		log.Errorf("Failed to verify signature: %v", err)
		respondError()
		return
	} else if !ok {
		log.Info("Invalid token")
		respondError()
		return
	}

	clientID, err := oidc.VerifyClientClaims(jwt, c.issuerURL)
	if err != nil {
		log.Errorf("Failed to verify JWT claims: %v", err)
		respondError()
		return
	}

	md, err := c.ciRepo.Metadata(clientID)
	if md == nil || err != nil {
		log.Errorf("Failed to find clientID: %s, error=%v", clientID, err)
		respondError()
		return
	}

	log.Infof("Authenticated token for client ID %s", clientID)
	c.next.ServeHTTP(w, r)
}

// getClientIDFromAuthorizedRequest will extract the clientID from the bearer token.
func getClientIDFromAuthorizedRequest(r *http.Request) (string, error) {
	jwt, err := oidc.ParseTokenFromRequest(r)
	if err != nil {
		return "", err
	}

	claims, err := jwt.Claims()
	if err != nil {
		return "", err
	}

	sub, ok, err := claims.StringClaim("sub")
	if err != nil {
		return "", fmt.Errorf("failed to parse 'sub' claim: %v", err)
	} else if !ok || sub == "" {
		return "", errors.New("missing required 'sub' claim")
	}

	return sub, nil
}
