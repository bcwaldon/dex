package server

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/coreos-inc/auth/pkg/log"

	"github.com/coreos-inc/auth/email"
	"github.com/coreos-inc/auth/session"
	"github.com/coreos-inc/auth/user"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
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

type resetPasswordTemplateData struct {
	Error        string
	Message      string
	Token        string
	DontShowForm bool
	Success      bool
}

type ResetPasswordHandler struct {
	tpl       *template.Template
	issuerURL url.URL
	um        *user.Manager
	keysFunc  func() ([]key.PublicKey, error)
}

type resetPasswordRequest struct {
	// A resetPasswordRequest starts with these objects.
	h    *ResetPasswordHandler
	r    *http.Request
	w    http.ResponseWriter
	data *resetPasswordTemplateData

	// These get filled in by sub-handlers.
	pwReset user.PasswordReset
}

func (h *ResetPasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := &resetPasswordRequest{
		h:    h,
		r:    r,
		w:    w,
		data: &resetPasswordTemplateData{},
	}
	req.HandleRequest()
}

func (r *resetPasswordRequest) HandleRequest() {
	switch r.r.Method {
	case "GET":
		r.handleGET()
		return
	case "POST":
		r.handlePOST()
		return
	default:
		writeAPIError(r.w, http.StatusMethodNotAllowed, newAPIError(errorInvalidRequest,
			"method not allowed"))
		return
	}
}

func (r *resetPasswordRequest) handleGET() {
	if !r.parseAndVerifyToken() {
		return
	}
	execTemplate(r.w, r.h.tpl, r.data)
}

func (r *resetPasswordRequest) handlePOST() {
	if !r.parseAndVerifyToken() {
		return
	}

	plaintext := r.r.FormValue("password")
	cbURL, err := r.h.um.ChangePassword(r.pwReset, plaintext)
	if err != nil {
		switch err {
		case user.ErrorPasswordAlreadyChanged:
			r.data.Error = "Link Expired"
			r.data.Message = "The link in your email is no longer valid. If you need to change your password, generate a new email."
			r.data.DontShowForm = true
			execTemplateWithStatus(r.w, r.h.tpl, r.data, http.StatusBadRequest)
			return
		case user.ErrorInvalidPassword:
			r.data.Error = "Invalid Password"
			r.data.Message = "Please choose a password which is at least six characters."
			execTemplateWithStatus(r.w, r.h.tpl, r.data, http.StatusBadRequest)
			return
		default:
			r.data.Error = "Error Processing Request"
			r.data.Message = "Plesae try again later."
			execTemplateWithStatus(r.w, r.h.tpl, r.data, http.StatusInternalServerError)
			return
		}

	}
	if cbURL == nil {
		r.data.Success = true
		execTemplate(r.w, r.h.tpl, r.data)
		return
	}

	http.Redirect(r.w, r.r, cbURL.String(), http.StatusSeeOther)
}

func (r *resetPasswordRequest) parseAndVerifyToken() bool {
	keys, err := r.h.keysFunc()
	if err != nil {
		log.Errorf("problem getting keys: %v", err)
		r.data.Error = "There's been an error processing your request."
		r.data.Message = "Plesae try again later."
		execTemplateWithStatus(r.w, r.h.tpl, r.data, http.StatusInternalServerError)
		return false
	}

	token := r.r.FormValue("token")
	pwReset, err := user.ParseAndVerifyPasswordResetToken(token, r.h.issuerURL, keys)
	if err != nil {
		log.Errorf("Reset Password unverifiable token: %v", err)
		r.data.Error = "Bad Password Reset Token"
		r.data.Message = "That was not a verifiable token."
		r.data.DontShowForm = true
		execTemplateWithStatus(r.w, r.h.tpl, r.data, http.StatusBadRequest)
		return false
	}
	r.pwReset = pwReset
	r.data.Token = token
	return true
}
