# oauthpkce

一个轻量的 Go OAuth2 + PKCE 工具库，主打纯 PKCE 公共客户端流程，支持：

- 生成 PKCE `code_verifier` / `code_challenge`
- 组装授权地址
- 启动本地回调服务接收授权码
- 使用纯 PKCE 交换授权码获取 Token
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

## 直接运行（自动开浏览器 + 等待回调 + 换 token）

项目内置了可执行入口：`cmd/oneclick/main.go`。

```powershell
Set-Location "C:\Users\Administrator\GolandProjects\oauthpkce"
$env:OAUTH_CLIENT_ID="your-client-id"
$env:OAUTH_AUTH_BASE="https://login.example.com"
$env:OAUTH_REDIRECT_URI="http://127.0.0.1:8765/callback"
$env:OAUTH_SCOPE="read"
go run ./cmd/oneclick
```

也可以全部用参数传入：

```powershell
Set-Location "C:\Users\Administrator\GolandProjects\oauthpkce"
go run ./cmd/oneclick --client-id "your-client-id" --auth-base "https://login.example.com" --redirect-uri "http://127.0.0.1:8765/callback" --scope "read" --timeout-seconds 180 --auto-open-browser=true --insecure-skip-verify=true
```

成功后会输出 JSON（包含 `auth_url`、`code_verifier`、`code`、`access_token`、`refresh_token` 等）。

## 快速示例

### 0) 一个函数完成纯 PKCE 授权 + 换 Token

```go
package main

import (
	"fmt"
	"time"

	"github.com/YuWan-030/oauthpkce"
)

func main() {
	res, err := oauthpkce.OneClickPKCEAuthorizeAndExchangeCompact(
		"your-client-id",
		"https://login.example.com",
		"http://127.0.0.1:8765/callback",
		"read",
		true,
		2*time.Minute,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Access Token:", res.AccessToken)
	fmt.Println("Refresh Token:", res.RefreshToken)
	fmt.Println("Code Verifier:", res.CodeVerifier)
}
```

### 1) 仅生成授权 URL

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

### 2) 使用纯 PKCE 交换授权码为 Token

```go
package main

import (
	"fmt"
	"time"

	"github.com/YuWan-030/oauthpkce"
)

func main() {
	token, err := oauthpkce.ExchangeAuthorizationCodeForPKCEToken(
		"your-client-id",
		"authorization-code",
		"code-verifier",
		"https://login.example.com",
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
	"encoding/json"
	"os"
	"time"

	"github.com/YuWan-030/oauthpkce"
)

func main() {
	res, err := oauthpkce.OneClickPKCEAuthorizeAndExchange(
		"your-client-id",
		"https://login.example.com",
		"http://127.0.0.1:8765/callback",
		"user_info",
		true,
		2*time.Minute,
	)
	if err != nil {
		panic(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}
```

## API 概览

- `GeneratePKCEVerifier(length int)`
- `GeneratePKCEChallenge(verifier, method string)`
- `PrepareOAuthLaunch(clientID, authBase, redirectURI, scope, state, method string)`
- `OpenBrowser(targetURL string)`
- `WaitForOAuthCallback(redirectURI string, timeout time.Duration)`
- `ExchangeAuthorizationCodeForPKCEToken(clientID, code, codeVerifier, authBase string, timeout time.Duration)`
- `RefreshPKCEAccessToken(clientID, refreshToken, authBase string, timeout time.Duration)`
- `RevokeToken(token, authBase, tokenTypeHint, clientID, clientSecret string, useBasicAuth bool, timeout time.Duration)`
- `ExtractTokenFields(tokenResponse *TokenResponse)`
- `OneClickOAuthStart(clientID, authBase, redirectURI, scope string, autoOpenBrowser bool, waitCallback bool, timeout time.Duration)`
- `OneClickPKCEAuthorizeAndExchange(clientID, authBase, redirectURI, scope string, autoOpenBrowser bool, timeout time.Duration)`
- `OneClickPKCEAuthorizeAndExchangeCompact(clientID, authBase, redirectURI, scope string, autoOpenBrowser bool, timeout time.Duration)`

## 测试

```bash
go test ./...
```

## 注意事项

- `code_verifier` 长度必须在 `[43, 128]`
- `code_challenge_method` 支持 `S256` 和 `PLAIN`
- 默认 `redirect_uri` 为 `http://127.0.0.1:8765/callback`
- 纯 PKCE 场景不需要 `client_secret`
- 生产环境建议优先使用 `S256`

