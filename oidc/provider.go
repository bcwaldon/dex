package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos-inc/auth/oauth2"
	phttp "github.com/coreos-inc/auth/pkg/http"
	"github.com/coreos-inc/auth/pkg/log"
	pnet "github.com/coreos-inc/auth/pkg/net"
	ptime "github.com/coreos-inc/auth/pkg/time"

	"github.com/jonboulle/clockwork"
)

const (
	discoveryConfigPath = "/.well-known/openid-configuration"
)

type ProviderConfig struct {
	Issuer                            string    `json:"issuer"`
	AuthEndpoint                      string    `json:"authorization_endpoint"`
	TokenEndpoint                     string    `json:"token_endpoint"`
	KeysEndpoint                      string    `json:"jwks_uri"`
	ResponseTypesSupported            []string  `json:"response_types_supported"`
	GrantTypesSupported               []string  `json:"grant_types_supported"`
	SubjectTypesSupported             []string  `json:"subject_types_supported"`
	IDTokenAlgValuesSupported         []string  `json:"id_token_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string  `json:"token_endpoint_auth_methods_supported"`
	ExpiresAt                         time.Time `json:"-"`
}

func (p ProviderConfig) SupportsGrantType(grantType string) bool {
	var supported []string
	if len(p.GrantTypesSupported) == 0 {
		// If omitted, the default value is ["authorization_code", "implicit"].
		// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		supported = []string{oauth2.GrantTypeAuthCode, oauth2.GrantTypeImplicit}
	} else {
		supported = p.GrantTypesSupported
	}

	for _, t := range supported {
		if t == grantType {
			return true
		}
	}
	return false
}

type ProviderConfigGetter interface {
	Get() (ProviderConfig, error)
}

type ProviderConfigSetter interface {
	Set(ProviderConfig) error
}

type ProviderConfigSyncer struct {
	from  ProviderConfigGetter
	to    ProviderConfigSetter
	clock clockwork.Clock
}

func NewProviderConfigSyncer(from ProviderConfigGetter, to ProviderConfigSetter) *ProviderConfigSyncer {
	return &ProviderConfigSyncer{
		from:  from,
		to:    to,
		clock: clockwork.NewRealClock(),
	}
}

func (s *ProviderConfigSyncer) Run() chan struct{} {
	stop := make(chan struct{})

	go func() {
		var failing bool
		var next time.Duration

		fail := func(err error) {
			if !failing {
				failing = true
				next = time.Second
			} else {
				next = ptime.ExpBackoff(next, time.Minute)
			}
			log.Errorf("Error syncing provider config, retrying in %v: %v", next, err)
		}

		for {
			cfg, err := s.from.Get()
			if err != nil {
				fail(err)
			} else {
				diff := cfg.ExpiresAt.Sub(s.clock.Now().UTC())
				if diff <= 0 {
					fail(errors.New("fetched provider config is already expired"))
				} else {
					failing = false
					next = diff / 2
					if err = s.to.Set(cfg); err != nil {
						fail(fmt.Errorf("error setting provider config: %v", err))
					} else {
						log.Infof("Updating provider config in %v: config=%#v", next, cfg)
					}
				}
			}

			select {
			case <-s.clock.After(next):
				continue
			case <-stop:
				return
			}
		}
	}()

	return stop
}

type httpProviderConfigGetter struct {
	hc        phttp.Client
	issuerURL string
	clock     clockwork.Clock
}

func NewHTTPProviderConfigGetter(hc phttp.Client, issuerURL string) *httpProviderConfigGetter {
	return &httpProviderConfigGetter{
		hc:        hc,
		issuerURL: issuerURL,
		clock:     clockwork.NewRealClock(),
	}
}

func (r *httpProviderConfigGetter) Get() (cfg ProviderConfig, err error) {
	req, err := http.NewRequest("GET", r.issuerURL+discoveryConfigPath, nil)
	if err != nil {
		return
	}

	resp, err := r.hc.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if err = json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return
	}

	maxAge, ok, err := phttp.CacheControlMaxAge(resp.Header.Get("Cache-Control"))
	if err != nil || !ok {
		err = errors.New("provider config missing cache headers")
		return
	}
	cfg.ExpiresAt = r.clock.Now().UTC().Add(maxAge)

	// The issuer value returned MUST be identical to the Issuer URL that was directly used to retrieve the configuration information.
	// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
	if !pnet.URLEqual(cfg.Issuer, r.issuerURL) {
		err = errors.New(`"issuer" in config does not match actual issuer URL`)
		return
	}

	return
}

func FetchProviderConfig(hc phttp.Client, issuerURL string) (ProviderConfig, error) {
	if hc == nil {
		hc = http.DefaultClient
	}

	g := NewHTTPProviderConfigGetter(hc, issuerURL)
	return g.Get()
}
