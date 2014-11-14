package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/coreos-inc/auth/oauth2"
	"github.com/coreos-inc/auth/oidc"
	phttp "github.com/coreos-inc/auth/pkg/http"
)

var (
	pathCallback = "/callback"
)

func main() {
	fs := flag.NewFlagSet("oidc-app", flag.ExitOnError)
	listen := fs.String("listen", "http://localhost:5555", "")
	clientID := fs.String("client-id", "", "")
	clientSecret := fs.String("client-secret", "", "")
	discovery := fs.String("discovery", "https://accounts.google.com", "")
	fs.Parse(os.Args[1:])

	if *clientID == "" {
		log.Fatal("--client-id must be set")
	}

	if *clientSecret == "" {
		log.Fatal("--client-secret must be set")
	}

	l, err := url.Parse(*listen)
	if err != nil {
		log.Fatalf("Unable to use --listen flag: %v", err)
	}

	_, p, err := net.SplitHostPort(l.Host)
	if err != nil {
		log.Fatalf("Unable to parse host from --listen flag: %v", err)
	}

	redirectURL := l
	redirectURL.Path = path.Join(redirectURL.Path, pathCallback)

	ci := oauth2.ClientIdentity{
		ID:     *clientID,
		Secret: *clientSecret,
	}

	var cfg *oidc.ProviderConfig
	for {
		cfg, err = oidc.FetchProviderConfig(http.DefaultClient, *discovery)
		if err == nil {
			break
		}

		sleep := 3 * time.Second
		log.Printf("Failed fetching provider config, trying again in %v: %v", sleep, err)
		time.Sleep(sleep)
	}

	log.Printf("Fetched provider config from %s: %#v", *discovery, *cfg)

	client := &oidc.Client{
		ProviderConfig: *cfg,
		ClientIdentity: ci,
		RedirectURL:    redirectURL.String(),
	}

	if err = client.RefreshKeys(); err != nil {
		log.Fatalf("Failed refreshing keys: %v", err)
	}

	hdlr := NewClientHandler(client)
	httpsrv := &http.Server{
		Addr:    fmt.Sprintf(":%s", p),
		Handler: hdlr,
	}

	log.Printf("binding to %s...", httpsrv.Addr)
	log.Fatal(httpsrv.ListenAndServe())
}

func NewClientHandler(c *oidc.Client) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/login", handleLoginFunc(c))
	mux.HandleFunc(pathCallback, handleCallbackFunc(c))
	return mux
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<a href='/login'>login</a>"))
}

func handleLoginFunc(c *oidc.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		oac, err := c.OAuthClient()
		if err != nil {
			panic("unable to proceed")
		}

		u, err := url.Parse(oac.AuthCodeURL("", "", ""))
		if err != nil {
			panic("unable to proceed")
		}
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}

func handleCallbackFunc(c *oidc.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			phttp.WriteError(w, http.StatusBadRequest, "code query param must be set")
			return
		}

		tok, err := c.ExchangeAuthCode(code)
		if err != nil {
			phttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("unable to verify auth code with issuer: %v", err))
			return
		}

		claims, err := tok.Claims()
		if err != nil {
			phttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("unable to construct claims: %v", err))
			return
		}

		w.Write([]byte(fmt.Sprintf("OK: %v", claims)))
	}
}
