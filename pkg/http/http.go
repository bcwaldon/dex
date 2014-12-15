package http

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos-inc/auth/pkg/log"
)

func WriteError(w http.ResponseWriter, code int, msg string) {
	e := struct {
		Error string `json:"error"`
	}{
		Error: msg,
	}
	b, err := json.Marshal(e)
	if err != nil {
		log.Errorf("Failed marshaling %#v to JSON: %v", e, err)
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

func CacheControlMaxAge(hdr string) (time.Duration, bool, error) {
	for _, field := range strings.Split(hdr, ",") {
		parts := strings.SplitN(strings.TrimSpace(field), "=", 2)
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		if k != "max-age" {
			continue
		}

		if len(parts) == 1 {
			return 0, true, errors.New("max-age has no value")
		}

		v := strings.TrimSpace(parts[1])
		if v == "" {
			return 0, true, errors.New("max-age has empty value")
		}

		age, err := strconv.Atoi(v)
		if err != nil {
			return 0, true, err
		}

		return time.Duration(age) * time.Second, true, nil
	}

	return 0, false, nil
}

// MergeQuery appends additional query values to an existing URL.
func MergeQuery(u url.URL, q url.Values) url.URL {
	uv := u.Query()
	for k, vs := range q {
		for _, v := range vs {
			uv.Add(k, v)
		}
	}
	u.RawQuery = uv.Encode()
	return u
}
