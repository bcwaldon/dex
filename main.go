package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/coreos-inc/auth/oidc"
)

var client *oidc.Client

func main() {
	// Configure new client
	client = oidc.NewClient("google", "https://accounts.google.com", "--client id--", "-- client secret --", "http://localhost:5555/callback")
	fmt.Println(client.Name)

	// discover provider configuration
	client.FetchProviderConfig()

	// fetch key material
	err := client.RefreshKeys()
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/protected-resource", handleProtected)

	log.Printf("listening on %s...", ":5555")
	log.Fatal(http.ListenAndServe(":5555", nil))
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
	result, err := client.HandleCallback(r)
	if err != nil {
		w.Write([]byte(err.Error()))
		panic(err)
	}

	log.Println(result.JWT)

	http.Redirect(w, r, "/protected-resource", http.StatusFound)
}

// Step 4: user is free to access protected resource
func handleProtected(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("protected resource here"))
}
