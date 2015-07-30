package server

import (
	"net/http"

	"github.com/julienschmidt/httprouter"

	"github.com/coreos-inc/auth/schema/workerschema"
)

var (
	UsersSubTree        = "/users"
	UsersListEndpoint   = addBasePath(UsersSubTree) + "/"
	UsersCreateEndooint = UsersListEndpoint
	UsersGetEndpoint    = addBasePath(UsersSubTree + "/:id")
)

type UserMgmtServer struct {
	userMgmtAPI interface{}
}

func NewUserMgmtServer(userMgmtAPI interface{}) *UserMgmtServer {
	return &UserMgmtServer{
		userMgmtAPI: userMgmtAPI,
	}
}

func (s *UserMgmtServer) HTTPHandler() http.Handler {
	r := httprouter.New()
	r.GET(UsersListEndpoint, s.listUsers)
	r.POST(UsersCreateEndooint, s.createUser)
	r.GET(UsersGetEndpoint, s.getUser)
	return r
}

func (s *UserMgmtServer) listUsers(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	userPage := workerschema.UserPage{
		Users: []*workerschema.User{
			&workerschema.User{
				Email: "test@example.com",
			},
		},
	}

	writeResponseWithBody(w, http.StatusOK, userPage)
}

func (s *UserMgmtServer) getUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	user := &workerschema.User{
		Id:    id,
		Email: "test@example.com",
	}
	writeResponseWithBody(w, http.StatusOK, user)
}

func (s *UserMgmtServer) createUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user := &workerschema.User{
		Id:    "NEW USER",
		Email: "test@example.com",
	}
	writeResponseWithBody(w, http.StatusOK, user)
}
