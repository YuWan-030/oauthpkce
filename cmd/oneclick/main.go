package main

import (
	"fmt"
	"time"

	"github.com/YuWan-030/oauthpkce"
)

func main() {
	res, err := oauthpkce.OneClickOAuthAuthorizeAndExchange(
		"cli_4f786a5d11afb431",
		"sec_08f2c88bbaea4d7ba754400bcd54ec50",
		"https://114.66.48.61:8900",
		"http://127.0.0.1:8765/callback",
		"read",
		true, // autoOpenBrowser
		2*time.Minute,
		true, // useBasicAuth
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Auth URL:", res.AuthURL)
	fmt.Println("Code:", res.CallbackResult.Code)
	fmt.Println("Access Token:", res.TokenResponse.AccessToken)
}
