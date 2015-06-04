package server

import (
	"net/http"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/oidc"
	"github.com/coreos-inc/auth/pkg/log"
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
}

var (
	errorMap = map[error]formError{
		user.ErrorInvalidName: formError{
			Field: "name",
			Error: "Please enter a valid name",
		},
		user.ErrorInvalidEmail: formError{
			Field: "email",
			Error: "Please enter a valid email",
		},
		user.ErrorDuplicateName: formError{
			Field: "name",
			Error: "That name is already in use; please choose another.",
		},
	}
)

func handleRegisterFunc(s *Server) http.HandlerFunc {
	tpl := s.RegisterTemplate

	errPage := func(w http.ResponseWriter, msg string, code string) {
		data := registerTemplateData{
			Error:   true,
			Message: msg,
			Code:    code,
		}
		execTemplate(w, tpl, data)
	}

	idx := makeConnectorMap(s.Connectors)

	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			errPage(w, "There was a problem processing your request.", "")
			return
		}

		// verify the user has a valid code.
		key := r.Form.Get("code")
		log.Debugf("code from form: %v", key)
		sessionID, err := s.SessionManager.ExchangeKey(key)
		if err != nil {
			errPage(w, "Please authenticate or something first.", "")
			return
		}

		// create a new code for them to use next time they hit the server.
		code, err := s.SessionManager.NewSessionKey(sessionID)
		if err != nil {
			errPage(w, "There was a server error.", "")
			return
		}
		ses, err := s.SessionManager.Get(sessionID)
		if err != nil || ses == nil {
			errPage(w, "There was a server error.", "")
			return
		}

		// determine whether or not this is a local or remote ID that is going
		// to be registered.
		idpc, ok := idx[ses.ConnectorID]
		if !ok {
			errPage(w, "There's been an error authenticating. Please try logging in again.", "")
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
		if len(formErrors) > 0 || !validate {
			data := registerTemplateData{
				Code:       code,
				Email:      email,
				Name:       name,
				Error:      false,
				Password:   password,
				FormErrors: formErrors,
			}
			execTemplate(w, tpl, data)
			return
		}

		var userID string
		if local {
			// DO local
			userID, err = s.UserManager.RegisterWithPassword(name, email, password, ses.ConnectorID)
			if err != nil {
				log.Errorf("reg fail: %v", err)
				errPage(w, "Reg Fail.", "")
				return
			}

			ses, err = s.SessionManager.AttachRemoteIdentity(sessionID, oidc.Identity{
				ID: userID,
			})
			if err != nil {
				log.Errorf("reg fail: %v", err)
				errPage(w, "Reg Fail.", "")
				return
			}

		} else {
			// DO remote
			if ses.Identity.ID == "" {
				errPage(w, "There's been an error authenticating. Please try logging in again.", "")
				return
			}
			rid := user.RemoteIdentity{
				ConnectorID: ses.ConnectorID,
				ID:          ses.Identity.ID,
			}
			userID, err = s.UserManager.RegisterWithRemoteIdentity(name, email, false, rid)
			if err != nil {
				fe, ok := errorMap[err]
				if ok {
					data := registerTemplateData{
						Code:       code,
						Email:      email,
						Name:       name,
						Error:      false,
						Password:   password,
						FormErrors: []formError{fe},
					}
					execTemplate(w, tpl, data)
					return
				}

				if err == user.ErrorDuplicateRemoteIdentity {
					errPage(w, "You already have an account registered with this identity", "")
					return
				}

				errPage(w, "There was an error authenticating. Please try again.", "")
				return
			}
		}

		// from server.Login
		ses, err = s.SessionManager.AttachUser(sessionID, userID)
		if err != nil {
			log.Errorf("reg fail: %v", err)
			errPage(w, "oops", "")
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
