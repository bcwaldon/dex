package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	phttp "github.com/coreos-inc/auth/pkg/http"
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
			log.Printf("Error syncing provider config, retrying in %v: %v", next, err)
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
						log.Printf("Provider config updated, config=%#v\nchecking again in %v", cfg, next)
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
	discovery string
	clock     clockwork.Clock
}

func NewHTTPProviderConfigGetter(hc phttp.Client, discovery string) *httpProviderConfigGetter {
	return &httpProviderConfigGetter{
		hc:        hc,
		discovery: discovery,
		clock:     clockwork.NewRealClock(),
	}
}

func (r *httpProviderConfigGetter) Get() (cfg ProviderConfig, err error) {
	req, err := http.NewRequest("GET", r.discovery+discoveryConfigPath, nil)
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

	ttl, ok, err := phttp.CacheControlMaxAge(resp.Header.Get("Cache-Control"))
	if err != nil || !ok {
		err = errors.New("provider config missing cache headers")
		return
	}
	maxAge := time.Duration(ttl) * time.Second
	cfg.ExpiresAt = r.clock.Now().UTC().Add(maxAge)

	// The issuer value returned MUST be identical to the Issuer URL that was directly used to retrieve the configuration information.
	// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation
	if !pnet.URLEqual(cfg.Issuer, r.discovery) {
		err = errors.New("issuer URL does not match discovery URL")
		return
	}

	return
}

func FetchProviderConfig(hc phttp.Client, discovery string) (ProviderConfig, error) {
	if hc == nil {
		hc = http.DefaultClient
	}

	g := NewHTTPProviderConfigGetter(hc, discovery)
	return g.Get()
}
