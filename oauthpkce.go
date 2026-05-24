package oauthpkce

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// 默认配置
const (
	DefaultAuthBase    = "https://localhost:8000"
	DefaultRedirectURI = "http://127.0.0.1:8765/callback"
)

// OAuthLaunchContext 保存发起授权时的上下文信息
type OAuthLaunchContext struct {
	ClientID            string `json:"client_id"`
	AuthURL             string `json:"auth_url"`
	State               string `json:"state"`
	CodeVerifier        string `json:"code_verifier"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	RedirectURI         string `json:"redirect_uri"`
}

// OAuthCallbackResult 接收到的回调数据
type OAuthCallbackResult struct {
	Code     string     `json:"code"`
	State    string     `json:"state"`
	Error    string     `json:"error"`
	RawQuery url.Values `json:"raw_query"`
}

// TokenResponse 令牌交换返回的标准结构
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

// FullResult 完整的一键授权返回结果
type FullResult struct {
	OAuthLaunchContext
	CallbackResult *OAuthCallbackResult `json:"callback,omitempty"`
	TokenResponse  *TokenResponse       `json:"token_response,omitempty"`
}

// --- 辅助工具函数 ---

func urlSafeB64WithoutPadding(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return urlSafeB64WithoutPadding(bytes)[:length], nil
}

// GeneratePKCEVerifier 生成 PKCE 校验码
func GeneratePKCEVerifier(length int) (string, error) {
	if length < 43 || length > 128 {
		return "", errors.New("PKCE code_verifier length must be in [43, 128]")
	}
	return generateRandomString(length)
}

// GeneratePKCEChallenge 生成 PKCE 挑战码
func GeneratePKCEChallenge(verifier string, method string) (string, error) {
	m := strings.ToUpper(method)
	if m == "" {
		m = "S256"
	}
	if m != "S256" && m != "PLAIN" {
		return "", errors.New("code_challenge_method must be 'S256' or 'PLAIN'")
	}
	if m == "PLAIN" {
		return verifier, nil
	}
	hasher := sha256.New()
	hasher.Write([]byte(verifier))
	return urlSafeB64WithoutPadding(hasher.Sum(nil)), nil
}

// OpenBrowser 跨平台打开浏览器
func OpenBrowser(targetURL string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", targetURL}
	case "darwin":
		cmd = "open"
		args = []string{targetURL}
	default: // linux, freebsd, etc.
		cmd = "xdg-open"
		args = []string{targetURL}
	}
	return exec.Command(cmd, args...).Start()
}

// --- 核心业务逻辑 ---

// PrepareOAuthLaunch 组装授权 URL 并生成 PKCE 参数
func PrepareOAuthLaunch(clientID, authBase, redirectURI, scope, state, method string) (*OAuthLaunchContext, error) {
	if strings.TrimSpace(clientID) == "" {
		return nil, errors.New("client_id is required")
	}
	if authBase == "" {
		authBase = DefaultAuthBase
	}
	if redirectURI == "" {
		redirectURI = DefaultRedirectURI
	}
	if method == "" {
		method = "S256"
	}

	var err error
	if state == "" {
		state, err = generateRandomString(24)
		if err != nil {
			return nil, err
		}
	}

	verifier, err := GeneratePKCEVerifier(64)
	if err != nil {
		return nil, err
	}

	challenge, err := GeneratePKCEChallenge(verifier, method)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", strings.ToUpper(method))

	authURL := fmt.Sprintf("%s/oauth/authorize?%s", strings.TrimRight(authBase, "/"), params.Encode())

	return &OAuthLaunchContext{
		ClientID:            clientID,
		AuthURL:             authURL,
		State:               state,
		CodeVerifier:        verifier,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		RedirectURI:         redirectURI,
	}, nil
}

// WaitForOAuthCallback 启动本地服务器捕获回调
func WaitForOAuthCallback(redirectURI string, timeout time.Duration) (*OAuthCallbackResult, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("redirect_uri must be http or https")
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		// 如果没有显式端口，试着补全
		if u.Scheme == "https" {
			host, port = u.Host, "443"
		} else {
			host, port = u.Host, "80"
		}
	}

	expectedPath := u.Path
	if expectedPath == "" {
		expectedPath = "/"
	}

	// 使用 Channel 传递结果
	resultChan := make(chan *OAuthCallbackResult, 1)

	// 创建并配置本地 HTTP 服务器
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    net.JoinHostPort(host, port),
		Handler: mux,
	}

	mux.HandleFunc(expectedPath, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		res := &OAuthCallbackResult{
			Code:     query.Get("code"),
			State:    query.Get("state"),
			Error:    query.Get("error"),
			RawQuery: query,
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if res.Error != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("OAuth callback received error. You can close this window."))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OAuth callback received successfully. You can close this window."))
		}

		// 发送结果，并在独立协程中优雅关闭服务器
		resultChan <- res
		go func() {
			_ = server.Shutdown(context.Background())
		}()
	})

	// 异步启动服务器
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// 如果启动失败（例如端口被占用），向 channel 发送 nil
			resultChan <- nil
		}
	}()

	// 阻塞等待：要么超时，要么收到回调
	select {
	case res := <-resultChan:
		if res == nil {
			return nil, errors.New("failed to start local callback server")
		}
		return res, nil
	case <-time.After(timeout):
		// 超时关闭服务器
		_ = server.Shutdown(context.Background())
		return nil, errors.New("oauth callback timeout")
	}
}

// ExchangeAuthorizationCodeForToken 交换 Token
func ExchangeAuthorizationCodeForToken(clientID, clientSecret, code, codeVerifier, authBase string, useBasicAuth bool, timeout time.Duration) (*TokenResponse, error) {
	if authBase == "" {
		authBase = DefaultAuthBase
	}

	tokenURL := fmt.Sprintf("%s/oauth/token", strings.TrimRight(authBase, "/"))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)

	var req *http.Request
	var err error

	if useBasicAuth {
		req, err = http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(clientID, clientSecret)
	} else {
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
		req, err = http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 使用包含超时的 Context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("token exchange failed: http %d, body=%s", resp.StatusCode, string(bodyBytes))
	}

	var tokenRes TokenResponse
	if err := json.Unmarshal(bodyBytes, &tokenRes); err != nil {
		return nil, fmt.Errorf("failed to parse token json: %w, raw=%s", err, string(bodyBytes))
	}

	return &tokenRes, nil
}

// OneClickOAuthAuthorizeAndExchange 一键完成授权和令牌交换
func OneClickOAuthAuthorizeAndExchange(clientID, clientSecret, authBase, redirectURI, scope string, autoOpenBrowser bool, timeout time.Duration, useBasicAuth bool) (*FullResult, error) {
	// 1. 准备 Launch Context
	launch, err := PrepareOAuthLaunch(clientID, authBase, redirectURI, scope, "", "S256")
	if err != nil {
		return nil, err
	}

	// 2. 自动打开浏览器
	if autoOpenBrowser {
		if err := OpenBrowser(launch.AuthURL); err != nil {
			return nil, fmt.Errorf("failed to open browser: %w", err)
		}
	}

	// 3. 同步等待回调
	callback, err := WaitForOAuthCallback(launch.RedirectURI, timeout)
	if err != nil {
		return nil, err
	}

	if callback.Error != "" {
		return nil, fmt.Errorf("oauth callback returned error: %s", callback.Error)
	}
	if callback.State != launch.State {
		return nil, errors.New("oauth callback state mismatch")
	}
	if callback.Code == "" {
		return nil, errors.New("oauth callback missing authorization code")
	}

	// 4. 交换 Token
	tokenTimeout := 30 * time.Second
	if timeout < tokenTimeout {
		tokenTimeout = timeout
	}

	tokenRes, err := ExchangeAuthorizationCodeForToken(clientID, clientSecret, callback.Code, launch.CodeVerifier, authBase, useBasicAuth, tokenTimeout)
	if err != nil {
		return nil, err
	}

	return &FullResult{
		OAuthLaunchContext: *launch,
		CallbackResult:     callback,
		TokenResponse:      tokenRes,
	}, nil
}
