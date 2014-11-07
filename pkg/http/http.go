package http

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

func WriteError(w http.ResponseWriter, code int, msg string) {
	e := struct {
		Error string `json:"error"`
	}{
		Error: msg,
	}
	b, err := json.Marshal(e)
	if err != nil {
		log.Printf("Failed marshaling %#v to JSON: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
}

// BasicAuth parses a username and password from the request's
// Authorization header. This was pulled from golang master:
// https://codereview.appspot.com/76540043
func BasicAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return
	}

	if !strings.HasPrefix(auth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}
