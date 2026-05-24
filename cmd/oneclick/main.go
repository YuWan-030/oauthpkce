package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/YuWan-030/oauthpkce"
)

func main() {
	clientID := flag.String("client-id", os.Getenv("OAUTH_CLIENT_ID"), "OAuth client_id")
	authBase := flag.String("auth-base", getEnvOrDefault("OAUTH_AUTH_BASE", oauthpkce.DefaultAuthBase), "OAuth server base URL")
	redirectURI := flag.String("redirect-uri", getEnvOrDefault("OAUTH_REDIRECT_URI", oauthpkce.DefaultRedirectURI), "OAuth redirect URI")
	scope := flag.String("scope", getEnvOrDefault("OAUTH_SCOPE", "read"), "OAuth scope")
	timeoutSeconds := flag.Int("timeout-seconds", 180, "Wait timeout in seconds")
	autoOpenBrowser := flag.Bool("auto-open-browser", true, "Open browser automatically")
	insecureSkipVerify := flag.Bool("insecure-skip-verify", true, "Skip TLS certificate verification for testing")
	flag.Parse()

	if *clientID == "" {
		_, _ = fmt.Fprintln(os.Stderr, "client-id is required")
		os.Exit(2)
	}

	if *insecureSkipVerify {
		if transport, ok := http.DefaultTransport.(*http.Transport); ok {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
	}

	res, err := oauthpkce.OneClickPKCEAuthorizeAndExchange(
		*clientID,
		*authBase,
		*redirectURI,
		*scope,
		*autoOpenBrowser,
		time.Duration(*timeoutSeconds)*time.Second,
	)
	if err != nil {
		panic(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		panic(err)
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
