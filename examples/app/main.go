package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"

	"github.com/coreos-inc/auth/oidc"
	oidchttp "github.com/coreos-inc/auth/oidc/http"
)

var (
	pathCallback = "/callback"
)

func main() {
	listen := flag.String("listen", "http://localhost:5555", "")
	clientID := flag.String("client-id", "", "")
	clientSecret := flag.String("client-secret", "", "")
	issuerURL := flag.String("issuer-url", "https://accounts.google.com", "")
	flag.Parse()

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

	client := oidc.NewClient(*issuerURL, *clientID, *clientSecret, redirectURL.String())

	if err = client.FetchProviderConfig(); err != nil {
		log.Fatalf("Failed fetching provider config: %v", err)
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
	mux.HandleFunc(pathCallback, oidchttp.NewClientCallbackHandlerFunc(c))
	return mux
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<a href='/login'>login</a>"))
}

func handleLoginFunc(c *oidc.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		acu := c.OAuth.AuthCodeURL("", "", "")
		u, _ := url.Parse(acu)
		q := u.Query()
		q.Set("uid", r.URL.Query().Get("uid"))
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}
