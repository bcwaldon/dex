package server

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/coreos-inc/auth/pkg/log"

	"github.com/coreos-inc/auth/email"
	"github.com/coreos-inc/auth/jose"
	"github.com/coreos-inc/auth/session"
	"github.com/coreos-inc/auth/user"
)

type sendResetPasswordEmailData struct {
	Error       bool
	Message     string
	EmailSent   bool
	Email       string
	ClientID    string
	RedirectURL string
}

type SendResetPasswordEmailHandler struct {
	tpl         *template.Template
	emailer     *email.TemplatizedEmailer
	sm          *session.SessionManager
	cr          ClientIdentityRepo
	ur          user.UserRepo
	pwi         user.PasswordInfoRepo
	issuerURL   url.URL
	fromAddress string
	signerFunc  func() (jose.Signer, error)
}

func (h *SendResetPasswordEmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.handleGET(w, r)
		return
	case "POST":
		h.handlePOST(w, r)
		return
	default:
		writeAPIError(w, http.StatusMethodNotAllowed, newAPIError(errorInvalidRequest,
			"method not allowed"))
		return
	}
}

func (h *SendResetPasswordEmailHandler) handleGET(w http.ResponseWriter, r *http.Request) {
	sessionKey := r.URL.Query().Get("session_key")
	if sessionKey != "" {
		clientID, redirectURL, err := h.exchangeKeyForClientAndRedirect(sessionKey)
		if err == nil {
			handleURL := *r.URL
			q := r.URL.Query()
			q.Del("session_key")
			q.Set("redirect_uri", redirectURL.String())
			q.Set("client_id", clientID)
			handleURL.RawQuery = q.Encode()
			http.Redirect(w, r, handleURL.String(), http.StatusSeeOther)
			return
		}
		// Even though we could not exchange the sessionKey to get a
		// redirect URL, we can still continue as if they didn't pass
		// one in, so we don't return here.
		log.Errorf("could not exchange sessionKey: %v", err)
	}
	data := sendResetPasswordEmailData{}
	h.fillData(r, &data)
	execTemplate(w, h.tpl, data)
}

func (h *SendResetPasswordEmailHandler) fillData(r *http.Request, data *sendResetPasswordEmailData) {
	data.Email = r.FormValue("email")
	clientID := r.FormValue("client_id")
	redirectURL := r.FormValue("redirect_uri")

	if redirectURL != "" && clientID != "" && h.validateRedirectURL(clientID, redirectURL) {
		data.ClientID = clientID
		data.RedirectURL = redirectURL
	}
}

func (h *SendResetPasswordEmailHandler) handlePOST(w http.ResponseWriter, r *http.Request) {
	data := sendResetPasswordEmailData{}
	h.fillData(r, &data)

	if !user.ValidEmail(data.Email) {
		h.errPage(w, "Please supply a valid email addresss.", http.StatusBadRequest, &data)
		return
	}

	data.EmailSent = true
	execTemplate(w, h.tpl, data)

	// We spawn this in new goroutine because we don't want anyone using timing
	// attacks to guess if an email address exists or not.
	go h.sendResetPasswordEmail(data.Email, data.RedirectURL, data.ClientID)
}

func (h *SendResetPasswordEmailHandler) validateRedirectURL(clientID string, redirectURL string) bool {
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		log.Errorf("Error parsing redirectURL: %v", err)
		return false
	}

	cm, err := h.cr.Metadata(clientID)
	if err != nil || cm == nil {
		log.Errorf("Error getting ClientMetadata: %v", err)
		return false
	}

	_, err = ValidRedirectURL(parsed, cm.RedirectURLs)
	if err != nil {
		log.Errorf("Invalid redirectURL for clientID: redirectURL:%q, clientID:%q", redirectURL, clientID)
		return false
	}

	return true
}

func (h *SendResetPasswordEmailHandler) errPage(w http.ResponseWriter, msg string, status int, data *sendResetPasswordEmailData) {
	data.Error = true
	data.Message = msg
	execTemplateWithStatus(w, h.tpl, data, status)
}

func (h *SendResetPasswordEmailHandler) internalError(w http.ResponseWriter, err error) {
	log.Errorf("Internal Error during sending password reset email: %v", err)
	h.errPage(w, "There was a problem processing your request.", http.StatusInternalServerError,
		&sendResetPasswordEmailData{})
}

func (h *SendResetPasswordEmailHandler) exchangeKeyForClientAndRedirect(key string) (string, url.URL, error) {
	id, err := h.sm.ExchangeKey(key)
	if err != nil {
		log.Errorf("error exchanging key: %v ", err)
		return "", url.URL{}, err
	}

	ses, err := h.sm.Kill(id)
	if err != nil {
		log.Errorf("error killing session: %v", err)
		return "", url.URL{}, err
	}

	return ses.ClientID, ses.RedirectURL, nil
}

func (h *SendResetPasswordEmailHandler) sendResetPasswordEmail(email, redirectURL, clientID string) error {
	usr, err := h.ur.GetByEmail(email)
	if err == user.ErrorNotFound {
		log.Errorf("No Such user for email: %q", email)
		return err
	}
	if err != nil {
		log.Errorf("Error getting user: %q", err)
		return err
	}

	pwi, err := h.pwi.Get(usr.ID)
	if err == user.ErrorNotFound {
		// TODO(bobbyrullo): In this case, maybe send a different email explaining that
		// they don't have a local password.
		log.Errorf("No Password for userID: %q", usr.ID)
		return err
	}
	if err != nil {
		log.Errorf("Error getting password: %q", err)
		return err
	}

	parsedRedir, err := url.Parse(redirectURL)
	if err != nil {
		log.Errorf("Error parsing redirect URL: %q", err)
		return err
	}

	signer, err := h.signerFunc()
	if err != nil {
		log.Errorf("error getting signer: %v", err)
		return err
	}

	passwordReset := user.NewPasswordReset(usr, pwi.Password, h.issuerURL,
		clientID, *parsedRedir, h.sm.ValidityWindow)
	token, err := passwordReset.Token(signer)
	if err != nil {
		log.Errorf("error getting tokenizing PasswordReset: %v", err)
		return err
	}

	resetURL := h.issuerURL
	resetURL.Path = httpPathResetPassword
	q := resetURL.Query()
	q.Set("token", token)
	resetURL.RawQuery = q.Encode()

	err = h.emailer.SendMail(h.fromAddress, "Reset your password.", "password-reset",
		map[string]interface{}{
			"email": usr.Email,
			"link":  resetURL.String(),
		}, usr.Email)

	if err != nil {
		log.Errorf("error sending email: %q", err)
	}
	return nil
}
