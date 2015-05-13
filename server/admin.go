package server

import (
	"encoding/json"
	"net/http"
	"path"

	"github.com/julienschmidt/httprouter"

	"github.com/coreos-inc/auth/admin"
	"github.com/coreos-inc/auth/pkg/log"
	"github.com/coreos-inc/auth/schema/adminschema"
)

const (
	AdminAPIVersion = "v1"
)

var (
	AdminGetEndpoint    = addBasePath("/admin/:id")
	AdminCreateEndpoint = addBasePath("/admin")
)

// AdminServer serves the admin API.
type AdminServer struct {
	adminAPI *admin.AdminAPI
}

func NewAdminServer(adminAPI *admin.AdminAPI) *AdminServer {
	return &AdminServer{
		adminAPI: adminAPI,
	}
}

func (s *AdminServer) HTTPHandler() http.Handler {
	r := httprouter.New()
	r.GET(AdminGetEndpoint, s.getAdmin)
	r.POST(AdminCreateEndpoint, s.createAdmin)
	return r
}

func (s *AdminServer) getAdmin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")

	admn, err := s.adminAPI.GetAdmin(id)
	if err != nil {
		s.writeError(w, err)
		return
	}

	writeResponseWithBody(w, http.StatusOK, admn)
}

func (s *AdminServer) createAdmin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	admn := adminschema.Admin{}
	err := json.NewDecoder(r.Body).Decode(&admn)
	if err != nil {
		writeInvalidRequest(w, "cannot parse JSON body")
		return
	}

	id, err := s.adminAPI.CreateAdmin(admn)
	if err != nil {
		s.writeError(w, err)
		return
	}

	admn.Id = id
	w.Header().Set("Location", AdminCreateEndpoint+"/"+id)
	writeResponseWithBody(w, http.StatusOK, admn)
}

func (s *AdminServer) writeError(w http.ResponseWriter, err error) {
	log.Errorf("Error calling admin API: %v: ", err)
	if adminErr, ok := err.(admin.Error); ok {
		writeAPIError(w, adminErr.Code, newAPIError(adminErr.Type, adminErr.Desc))
		return
	}

	writeAPIError(w, http.StatusInternalServerError, newAPIError(errorServerError, err.Error()))
}

func writeInvalidRequest(w http.ResponseWriter, msg string) {
	writeAPIError(w, http.StatusBadRequest, newAPIError(errorInvalidRequest, msg))
}

func addBasePath(s string) string {
	return path.Join(httpPathAPI, APIVersion, s)
}
