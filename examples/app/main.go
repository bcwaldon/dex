package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/coreos-inc/auth/oidc"
)

var (
	callbackURL = "http://localhost:5555/callback"

	client   *oidc.Client
	bindPort string
)

func init() {
	u, err := url.Parse(callbackURL)
	if err != nil {
		log.Fatalf("callbackURL %q invalid: %v", callbackURL, err)
	}

	_, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		log.Fatalf("Unable to determine port in callbackURL %q: %v", callbackURL, err)
	}

	bindPort = fmt.Sprintf(":%s", p)
}

func main() {
	var clientID = flag.String("client-id", "", "")
	var clientSecret = flag.String("client-secret", "", "")
	var issuerURL = flag.String("issuer-url", "https://accounts.google.com", "")
	flag.Parse()

	if *clientID == "" {
		log.Fatal("--client-id must be set")
	}

	if *clientSecret == "" {
		log.Fatal("--client-secret must be set")
	}

	// Configure new client
	client = oidc.NewClient(*issuerURL, *clientID, *clientSecret, callbackURL)

	// discover provider configuration
	err := client.FetchProviderConfig()
	if err != nil {
		log.Fatalf("Failed fetching provider config: %v", err)
	}

	// fetch key material
	err = client.RefreshKeys()
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/protected-resource", handleProtected)

	log.Printf("listening on %s...", bindPort)
	log.Fatal(http.ListenAndServe(bindPort, nil))
}

// Step 1: ask user to login
func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<a href='/login'>login</a>"))
}

// Step 2: useer is redirected to provider auth page.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	err := client.SendToAuthPage(w, r, "")
	if err != nil {
		panic(err)
	}
}

// Step 3: provider redirects to oauth callback
func handleCallback(w http.ResponseWriter, r *http.Request) {
	//TODO(bcwaldon): Actually handle the result from this
	_, err := client.HandleCallback(r)
	if err != nil {
		log.Printf("Unable to handle OAuth2 callback: %v", err)
		w.Write([]byte(err.Error()))
		return
	}

	http.Redirect(w, r, "/protected-resource", http.StatusFound)
}

// Step 4: user is free to access protected resource
func handleProtected(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("protected resource here"))
}
