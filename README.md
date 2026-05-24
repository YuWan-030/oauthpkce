# oauthpkce

一个轻量的 Go OAuth2 + PKCE 工具库，支持：

- 生成 PKCE `code_verifier` / `code_challenge`
- 组装授权地址
- 启动本地回调服务接收授权码
- 交换授权码获取 Token
- 一键完成授权 + 回调 + Token 交换
- 刷新 Token / 撤销 Token

## 安装

```bash
go get github.com/YuWan-030/oauthpkce@latest
```

## 导入

```go
import "github.com/YuWan-030/oauthpkce"
```

## 快速示例

## 直接运行（自动开浏览器 + 等待回调 + 换 token）

项目内置了可执行入口：`cmd/oneclick/main.go`。

```powershell
Set-Location "C:\Users\Administrator\GolandProjects\oauthpkce"
$env:OAUTH_CLIENT_ID="your-client-id"
$env:OAUTH_CLIENT_SECRET="your-client-secret"
$env:OAUTH_AUTH_BASE="https://login.example.com"
$env:OAUTH_REDIRECT_URI="http://127.0.0.1:8765/callback"
$env:OAUTH_SCOPE="read"
go run ./cmd/oneclick
```

也可以全部用参数传入：

```powershell
Set-Location "C:\Users\Administrator\GolandProjects\oauthpkce"
go run ./cmd/oneclick --client-id "your-client-id" --client-secret "your-client-secret" --auth-base "https://login.example.com" --redirect-uri "http://127.0.0.1:8765/callback" --scope "read" --timeout-seconds 180 --use-basic-auth=true --auto-open-browser=true
```

成功后会输出 JSON（包含 `access_token`、`refresh_token`、`code_verifier` 等）。

### 0) 一个函数完成授权+换 Token

```go
package main

import (
	"fmt"
	"time"

	"github.com/YuWan-030/oauthpkce"
)

func main() {
	res, err := oauthpkce.OneClickOAuthAuthorizeAndExchangeCompact(
		"your-client-id",
		"your-client-secret",
		"https://login.example.com",
		"http://127.0.0.1:8765/callback",
		"read",
		true,
		2*time.Minute,
		true,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Access Token:", res.AccessToken)
	fmt.Println("Refresh Token:", res.RefreshToken)
	fmt.Println("Code Verifier:", res.CodeVerifier)
}
```

### 1) 仅生成授权 URL（推荐先用这个）

```go
package main

import (
	"fmt"

	"github.com/YuWan-030/oauthpkce"
)

func main() {
	ctx, err := oauthpkce.PrepareOAuthLaunch(
		"your-client-id",
		"https://login.example.com",
		"http://127.0.0.1:8765/callback",
		"user_info",
		"custom-state",
		"S256",
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Auth URL:", ctx.AuthURL)
	fmt.Println("Code Verifier:", ctx.CodeVerifier)
}
```

### 2) 交换授权码为 Token

```go
package main

import (
	"fmt"
	"time"

	"github.com/YuWan-030/oauthpkce"
)

func main() {
	token, err := oauthpkce.ExchangeAuthorizationCodeForToken(
		"your-client-id",
		"your-client-secret",
		"authorization-code",
		"code-verifier",
		"https://login.example.com",
		true, // use basic auth
		5*time.Second,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Access Token:", token.AccessToken)
}
```

### 3) 一键流程（自动开浏览器 + 等待回调 + 换 token）

```go
package main

import (
	"fmt"
	"time"

	"github.com/YuWan-030/oauthpkce"
)

func init() {
	// 💡 核心注入：修改全局默认 Transport，跳过不安全的 HTTPS 证书校验
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
}

func main() {
	res, err := oauthpkce.OneClickOAuthAuthorizeAndExchange(
		"your-client-id",
		"your-client-secret",
		"https://login.example.com",
		"http://127.0.0.1:8765/callback",
		"user_info",
		true,  // autoOpenBrowser
		2*time.Minute,
		true,  // useBasicAuth
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Auth URL:", res.AuthURL)
	fmt.Println("Code:", res.CallbackResult.Code)
	fmt.Println("Access Token:", res.TokenResponse.AccessToken)
	fmt.Println("Refresh Token:", res.TokenResponse.RefreshToken)
}
```

## API 概览

- `GeneratePKCEVerifier(length int)`
- `GeneratePKCEChallenge(verifier, method string)`
- `PrepareOAuthLaunch(clientID, authBase, redirectURI, scope, state, method string)`
- `OpenBrowser(targetURL string)`
- `WaitForOAuthCallback(redirectURI string, timeout time.Duration)`
- `ExchangeAuthorizationCodeForToken(clientID, clientSecret, code, codeVerifier, authBase string, useBasicAuth bool, timeout time.Duration)`
- `RefreshAccessToken(clientID, clientSecret, refreshToken, authBase string, useBasicAuth bool, timeout time.Duration)`
- `RevokeToken(token, authBase, tokenTypeHint, clientID, clientSecret string, useBasicAuth bool, timeout time.Duration)`
- `ExtractTokenFields(tokenResponse *TokenResponse)`
- `OneClickOAuthStart(clientID, authBase, redirectURI, scope string, autoOpenBrowser bool, waitCallback bool, timeout time.Duration)`
- `OneClickOAuthAuthorizeAndExchange(clientID, clientSecret, authBase, redirectURI, scope string, autoOpenBrowser bool, timeout time.Duration, useBasicAuth bool)`
- `OneClickOAuthAuthorizeAndExchangeCompact(clientID, clientSecret, authBase, redirectURI, scope string, autoOpenBrowser bool, timeout time.Duration, useBasicAuth bool)`

## 测试

```bash
go test ./...
```

## 注意事项

- `code_verifier` 长度必须在 `[43, 128]`
- `code_challenge_method` 支持 `S256` 和 `PLAIN`
- 默认 `redirect_uri` 为 `http://127.0.0.1:8765/callback`
- 生产环境建议优先使用 `S256`

