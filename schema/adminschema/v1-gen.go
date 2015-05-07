// Package adminschema provides access to the Authd Admin API.
//
// See http://github.com/coreos-inc/auth
//
// Usage example:
//
//   import "github.com/coreos-inc/auth/Godeps/_workspace/src/google.golang.org/api/adminschema/v1"
//   ...
//   adminschemaService, err := adminschema.New(oauthHttpClient)
package adminschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coreos-inc/auth/Godeps/_workspace/src/google.golang.org/api/googleapi"
)

// Always reference these packages, just in case the auto-generated code
// below doesn't.
var _ = bytes.NewBuffer
var _ = strconv.Itoa
var _ = fmt.Sprintf
var _ = json.NewDecoder
var _ = io.Copy
var _ = url.Parse
var _ = googleapi.Version
var _ = errors.New
var _ = strings.Replace

const apiId = "authd:v1"
const apiName = "adminschema"
const apiVersion = "v1"
const basePath = "$ENDPOINT/api/v1/"

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	return s, nil
}

type Service struct {
	client   *http.Client
	BasePath string // API endpoint base URL
}
