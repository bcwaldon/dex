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
	Name       string
	Email      string
	Code       string
	Password   string
	Local      bool
}

var (
	errToFormErrorMap = map[error]formError{
		user.ErrorInvalidName: formError{
			Field: "name",
			Error: "Please enter a valid name",
		},
		user.ErrorInvalidEmail: formError{
			Field: "email",
			Error: "Please enter a valid email",
		},
		user.ErrorInvalidPassword: formError{
			Field: "password",
			Error: "Please enter a valid password",
		},
		user.ErrorDuplicateName: formError{
			Field: "name",
			Error: "That name is already in use; please choose another.",
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

		validate := r.Form.Get("validate") == "1"
		formErrors := []formError{}
		name := r.Form.Get("name")
		email := r.Form.Get("email")
		password := r.Form.Get("password")
		if validate {
			if name == "" {
				formErrors = append(formErrors, formError{"name", "Please supply a valid name"})
			}
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
			Name:     name,
			Password: password,
			Local:    local,
		}
		if len(formErrors) > 0 || !validate {
			data.FormErrors = formErrors
			execTemplate(w, tpl, data)
			return
		}

		var userID string
		if local {
			userID, err = registerFromLocalConnector(
				s.UserManager,
				s.SessionManager,
				ses,
				name, email, password)
		} else {
			userID, err = registerFromRemoteConnector(
				s.UserManager,
				ses,
				name,
				email)
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

		ru := ses.RedirectURL
		q := ru.Query()
		q.Set("code", code)
		q.Set("state", ses.ClientState)
		ru.RawQuery = q.Encode()
		w.Header().Set("Location", ru.String())
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
}

func registerFromLocalConnector(userManager *user.Manager, sessionManager *session.SessionManager, ses *session.Session, name, email, password string) (string, error) {
	userID, err := userManager.RegisterWithPassword(name, email, password, ses.ConnectorID)
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

func registerFromRemoteConnector(userManager *user.Manager, ses *session.Session, name, email string) (string, error) {
	if ses.Identity.ID == "" {
		//errPage(w, "There's been an error authenticating. Please try logging in again.", "")
		return "", errors.New("")
	}
	rid := user.RemoteIdentity{
		ConnectorID: ses.ConnectorID,
		ID:          ses.Identity.ID,
	}
	userID, err := userManager.RegisterWithRemoteIdentity(name, email, false, rid)
	if err != nil {
		return "", err
	}

	return userID, nil
}

func errToFormErrors(err error) []formError {
	fes := []formError{}
	fe, ok := errToFormErrorMap[err]
	if ok {
		log.Errorf("OK IN HERE")
		fes = append(fes, fe)
	}
	log.Errorf("NOT OK IN HERE")
	return fes
}
