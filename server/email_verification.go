package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos-inc/auth/email"
	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/log"
	"github.com/coreos-inc/auth/user"
)

// handleVerifyEmailResendFunc will resend an email-verification email given a valid JWT for the user and a redirect URL.
// This handler is meant to be wrapped in clientTokenMiddleware, so a valid
// bearer token for the client is expected to be present.
// The user's JWT should be in the "token" parameter and the redirect URL should
// be in the "redirect_uri" param. Note that this re
func handleVerifyEmailResendFunc(
	issuerURL url.URL,
	verifyURL url.URL,
	expiryTime time.Duration,
	srvKeysFunc func() ([]key.PublicKey, error),
	signerFunc func() (jose.Signer, error),
	emailer *email.TemplatizedEmailer,
	emailFromAddress string,
	userRepo user.UserRepo,
	clientIdentityRepo ClientIdentityRepo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var params struct {
			Token       string `json:"token"`
			RedirectURI string `json:"redirectURI"`
		}
		err := decoder.Decode(&params)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, newAPIError(errorInvalidRequest,
				"unable to parse body as JSON"))
			return
		}

		token := params.Token
		if token == "" {
			writeAPIError(w, http.StatusBadRequest,
				newAPIError(errorInvalidRequest, "missing valid JWT"))
			return
		}

		clientID, err := getClientIDFromAuthorizedRequest(r)
		if err != nil {
			log.Debugf("Failed to extract clientID: %v", err)
			writeAPIError(w, http.StatusUnauthorized,
				newAPIError(errorInvalidRequest, "cilent could not be extracted from bearer token."))
			return
		}

		cm, err := clientIdentityRepo.Metadata(clientID)
		if err != nil {
			log.Errorf("Error getting ClientMetadata: %v", err)
			writeAPIError(w, http.StatusInternalServerError,
				newAPIError(errorServerError, "could not send email at this time"))
			return
		}
		if cm == nil {
			log.Debugf("No such client: %v", err)
			writeAPIError(w, http.StatusBadRequest,
				newAPIError(errorInvalidRequest, "invalid client_id"))
			return
		}

		noop := func() error { return nil }
		keysFunc := func() []key.PublicKey {
			keys, err := srvKeysFunc()
			if err != nil {
				log.Errorf("Error getting keys: %v", err)
			}
			return keys
		}

		jwt, err := jose.ParseJWT(token)
		if err != nil {
			log.Debugf("Failed to Parse JWT: %v", err)
			writeAPIError(w, http.StatusBadRequest,
				newAPIError(errorInvalidRequest, "token could not be parsed"))
			return
		}

		verifier := oidc.NewJWTVerifier(issuerURL.String(), clientID, noop, keysFunc)
		if err := verifier.Verify(jwt); err != nil {
			log.Debugf("Failed to Verify JWT: %v", err)
			writeAPIError(w, http.StatusUnauthorized,
				newAPIError(errorAccessDenied, "invalid token could not be verified"))
			return
		}

		claims, err := jwt.Claims()
		if err != nil {
			log.Debugf("Failed to extract claims from JWT: %v", err)
			writeAPIError(w, http.StatusBadRequest,
				newAPIError(errorInvalidRequest, "invalid token could not be parsed"))
			return
		}

		sub, ok, err := claims.StringClaim("sub")
		if err != nil || !ok || sub == "" {
			log.Debugf("Failed to extract sub claim from JWT: err:%q ok:%v", err, ok)
			writeAPIError(w, http.StatusBadRequest,
				newAPIError(errorInvalidRequest, "could not extract sub claim from token"))
			return
		}

		usr, err := userRepo.Get(sub)
		if err != nil {
			if err == user.ErrorNotFound {
				log.Debugf("Failed to find user specified by token: %v", err)
				writeAPIError(w, http.StatusBadRequest,
					newAPIError(errorInvalidRequest, "could not find user"))
				return
			}
			log.Errorf("Failed to fetch user: %v", err)
			writeAPIError(w, http.StatusInternalServerError,
				newAPIError(errorServerError, "could not send email at this time"))
			return
		}

		aud, _, _ := claims.StringClaim("aud")
		if aud != clientID {
			log.Debugf("aud of token and sub of bearer token must match: %v", err)
			writeAPIError(w, http.StatusForbidden,
				newAPIError(errorAccessDenied, "JWT is from another client."))
			return
		}

		redirectURLStr := params.RedirectURI
		if redirectURLStr == "" {
			log.Debugf("No redirect URL: %v", err)
			writeAPIError(w, http.StatusBadRequest,
				newAPIError(errorInvalidRequest, "must provide a redirect_uri"))
			return
		}

		redirectURL, err := url.Parse(redirectURLStr)
		if err != nil {
			log.Debugf("Unparsable URL: %v", err)
			writeAPIError(w, http.StatusBadRequest,
				newAPIError(errorInvalidRequest, "invalid redirect_uri"))
			return
		}

		*redirectURL, err = ValidRedirectURL(redirectURL, cm.RedirectURLs)
		if err != nil {
			switch err {
			case (ErrorInvalidRedirectURL):
				log.Debugf("Request provided unregistered redirect URL: %s", redirectURLStr)
				writeAPIError(w, http.StatusBadRequest,
					newAPIError(errorInvalidRequest, "invalid redirect_uri"))
				return
			case (ErrorNoValidRedirectURLs):
				log.Errorf("There are no registered URLs for the requested client: %s", redirectURL)
				writeAPIError(w, http.StatusBadRequest,
					newAPIError(errorInvalidRequest, "invalid redirect_uri"))
				return
			}
		}

		signer, err := signerFunc()
		if err != nil {
			log.Errorf("Could not create a signer: %v", err)
			writeAPIError(w, http.StatusInternalServerError,
				newAPIError(errorServerError, "could not send email at this time"))
			return
		}

		err = sendEmailVerification(usr,
			clientID,
			verifyURL,
			*redirectURL,
			expiryTime,
			emailFromAddress,
			emailer,
			issuerURL,
			signer)

		if err != nil {
			log.Errorf("Failed to send email verification email: %v", err)
			writeAPIError(w, http.StatusInternalServerError,
				newAPIError(errorServerError, "could not send email at this time"))
			return
		}
		writeResponseWithBody(w, http.StatusOK, struct{}{})
	}
}

type emailVerifiedTemplateData struct {
	Error   string
	Message string
}

func handleEmailVerifyFunc(verifiedTpl *template.Template, issuer url.URL, keysFunc func() ([]key.PublicKey,
	error), userManager *user.Manager) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		token := q.Get("token")

		keys, err := keysFunc()
		if err != nil {
			execTemplateWithStatus(w, verifiedTpl, emailVerifiedTemplateData{
				Error:   "There's been an error processing your request.",
				Message: "Plesae try again later.",
			}, http.StatusInternalServerError)
			return
		}

		ev, err := user.ParseAndVerifyEmailVerificationToken(token, issuer, keys)
		if err != nil {
			execTemplateWithStatus(w, verifiedTpl, emailVerifiedTemplateData{
				Error:   "Bad Email Verification Token",
				Message: "That was not a verifiable token.",
			}, http.StatusBadRequest)
			return
		}

		cbURL, err := userManager.VerifyEmail(ev)
		if err != nil {
			switch err {
			case user.ErrorEmailAlreadyVerified:
				execTemplateWithStatus(w, verifiedTpl, emailVerifiedTemplateData{
					Error:   "Email Address already verified.",
					Message: "The email address that this link verifies has already been verified.",
				}, http.StatusBadRequest)
			case user.ErrorEVEmailDoesntMatch:
				execTemplateWithStatus(w, verifiedTpl, emailVerifiedTemplateData{
					Error:   "Email Address in token doesn't match current email.",
					Message: "The email address that this link is not the same as the most recent email on file. Perhaps you have a more recent verification link?",
				}, http.StatusBadRequest)
			default:
				execTemplateWithStatus(w, verifiedTpl, emailVerifiedTemplateData{
					Error:   "There's been an error processing your request.",
					Message: "Plesae try again later.",
				}, http.StatusInternalServerError)
			}
			return
		}

		http.Redirect(w, r, cbURL.String(), http.StatusSeeOther)
	}
}

func sendEmailVerification(usr user.User,
	clientID string,
	verifyURL url.URL,
	redirectURL url.URL,
	expires time.Duration,
	from string,
	emailer *email.TemplatizedEmailer,
	issuerURL url.URL,
	signer jose.Signer) error {
	ev := user.NewEmailVerification(usr, clientID, issuerURL, redirectURL, expires)

	token, err := ev.Token(signer)
	if err != nil {
		return err
	}

	q := verifyURL.Query()
	q.Set("token", token)
	verifyURL.RawQuery = q.Encode()

	err = emailer.SendMail(from, "Please verify your email address.", "verify-email",
		map[string]interface{}{
			"email": usr.Email,
			"link":  verifyURL.String(),
		}, usr.Email)
	if err != nil {
		return err
	}

	return nil
}