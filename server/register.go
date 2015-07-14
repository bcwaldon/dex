package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/log"
	"github.com/coreos-inc/auth/session"
	"github.com/coreos-inc/auth/user"
)

type formError struct {
	Field string
	Error string
}

type registerTemplateData struct {
	Error      bool
	FormErrors []formError
	Message    string
	Email      string
	Code       string
	Password   string
	Local      bool
}

var (
	errToFormErrorMap = map[error]formError{
		user.ErrorInvalidEmail: formError{
			Field: "email",
			Error: "Please enter a valid email",
		},
		user.ErrorInvalidPassword: formError{
			Field: "password",
			Error: "Please enter a valid password",
		},
		user.ErrorDuplicateEmail: formError{
			Field: "email",
			Error: "That email is already in use; please choose another.",
		},
	}
)

func handleRegisterFunc(s *Server) http.HandlerFunc {
	tpl := s.RegisterTemplate

	errPage := func(w http.ResponseWriter, msg string, code string, status int) {
		data := registerTemplateData{
			Error:   true,
			Message: msg,
			Code:    code,
		}
		execTemplateWithStatus(w, tpl, data, status)
	}

	internalError := func(w http.ResponseWriter, err error) {
		log.Errorf("Internal Error during registration: %v", err)
		errPage(w, "There was a problem processing your request.", "", http.StatusInternalServerError)
	}

	idx := makeConnectorMap(s.Connectors)

	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			internalError(w, err)
			return
		}

		// verify the user has a valid code.
		key := r.Form.Get("code")
		sessionID, err := s.SessionManager.ExchangeKey(key)
		if err != nil {
			errPage(w, "Please authenticate before registering.", "", http.StatusUnauthorized)
			return
		}

		// create a new code for them to use next time they hit the server.
		code, err := s.SessionManager.NewSessionKey(sessionID)
		if err != nil {
			internalError(w, err)
			return
		}
		ses, err := s.SessionManager.Get(sessionID)
		if err != nil || ses == nil {
			return
		}

		// determine whether or not this is a local or remote ID that is going
		// to be registered.
		idpc, ok := idx[ses.ConnectorID]
		if !ok {
			internalError(w, fmt.Errorf("no such IDPC: %v", ses.ConnectorID))
			return
		}
		_, local := idpc.(*connector.LocalConnector)

		// Does the email comes from a trusted provider?
		trustedEmail := ses.Identity.Email != "" && idpc.TrustedEmailProvider()
		validate := r.Form.Get("validate") == "1"
		formErrors := []formError{}
		email := r.Form.Get("email")

		// only auto-populate the first time the page is GETted, not on
		// subsequent POSTs
		if email == "" && r.Method == "GET" {
			email = ses.Identity.Email
		}

		password := r.Form.Get("password")
		if validate {
			if email == "" {
				formErrors = append(formErrors, formError{"email", "Please supply a valid email"})
			}
			if local && password == "" {
				formErrors = append(formErrors, formError{"password", "Please supply a valid password"})
			}
		}

		data := registerTemplateData{
			Code:     code,
			Email:    email,
			Password: password,
			Local:    local,
		}

		// If there are form errors or this is the initial request
		// (i.e. validate==false), and we are not going to auto-submit a
		// trusted email, then show the form.
		if (len(formErrors) > 0 || !validate) && !trustedEmail {
			data.FormErrors = formErrors
			if !validate {
				execTemplate(w, tpl, data)
			} else {
				execTemplateWithStatus(w, tpl, data, http.StatusBadRequest)
			}
			return
		}

		var userID string
		if local {
			userID, err = registerFromLocalConnector(
				s.UserManager,
				s.SessionManager,
				ses,
				email, password)
		} else {
			if trustedEmail {
				// in the case of a trusted email provider, make sure we are
				// getting the email address from the session, not from the
				// query string, to prevent forgeries.
				email = ses.Identity.Email
			}
			userID, err = registerFromRemoteConnector(
				s.UserManager,
				ses,
				email,
				trustedEmail)
		}

		if err != nil {
			formErrors := errToFormErrors(err)
			if len(formErrors) > 0 {
				data.FormErrors = formErrors
				execTemplate(w, tpl, data)
				return
			} else {
				if err == user.ErrorDuplicateRemoteIdentity {
					errPage(w, "You already have an account registered with this identity", "", http.StatusConflict)
					return
				}
				internalError(w, err)
				return
			}
		}
		ses, err = s.SessionManager.AttachUser(sessionID, userID)
		if err != nil {
			internalError(w, err)
			return
		}

		usr, err := s.UserRepo.Get(userID)
		if err != nil {
			internalError(w, err)
			return
		}

		signer, err := s.KeyManager.Signer()
		if err != nil {
			log.Errorf("Error sending email verification: %v", err)
			goto Redirect
		}

		if !trustedEmail {
			err = sendEmailVerification(usr,
				ses.ClientID,
				s.absURL(httpPathEmailVerify),
				ses.RedirectURL,
				s.SessionManager.ValidityWindow,
				s.EmailFromAddress,
				s.Emailer,
				s.IssuerURL,
				signer)

			if err != nil {
				log.Errorf("Error sending email verification: %v", err)
			}
		}

	Redirect:

		ru := ses.RedirectURL
		q := ru.Query()
		q.Set("code", code)
		q.Set("state", ses.ClientState)
		ru.RawQuery = q.Encode()
		w.Header().Set("Location", ru.String())
		w.WriteHeader(http.StatusSeeOther)
		return
	}
}

func registerFromLocalConnector(userManager *user.Manager, sessionManager *session.SessionManager, ses *session.Session, email, password string) (string, error) {
	userID, err := userManager.RegisterWithPassword(email, password, ses.ConnectorID)
	if err != nil {
		return "", err
	}

	ses, err = sessionManager.AttachRemoteIdentity(ses.ID, oidc.Identity{
		ID: userID,
	})
	if err != nil {
		return "", err
	}
	return userID, nil
}

func registerFromRemoteConnector(userManager *user.Manager, ses *session.Session, email string, emailVerified bool) (string, error) {
	if ses.Identity.ID == "" {
		return "", errors.New("No Identity found in session.")
	}
	rid := user.RemoteIdentity{
		ConnectorID: ses.ConnectorID,
		ID:          ses.Identity.ID,
	}
	userID, err := userManager.RegisterWithRemoteIdentity(email, emailVerified, rid)
	if err != nil {
		return "", err
	}

	return userID, nil
}

func errToFormErrors(err error) []formError {
	fes := []formError{}
	fe, ok := errToFormErrorMap[err]
	if ok {
		fes = append(fes, fe)
	}
	return fes
}
