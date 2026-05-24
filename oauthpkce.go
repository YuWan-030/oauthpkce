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

// TokenFields 常用 Token 字段
type TokenFields struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

// OAuthStartResult 一键启动阶段返回结果
type OAuthStartResult struct {
	OAuthLaunchContext
	CallbackResult *OAuthCallbackResult `json:"callback,omitempty"`
	StateOK        bool                 `json:"state_ok"`
}

// CompactResult 一键授权后的精简结果
type CompactResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	Code         string `json:"code"`
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
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

func joinOAuthEndpoint(base, path string) string {
	trimmedBase := strings.TrimRight(strings.TrimSpace(base), "/")
	if trimmedBase == "" {
		return path
	}
	if strings.HasSuffix(strings.ToLower(trimmedBase), strings.ToLower(path)) {
		return trimmedBase
	}
	return trimmedBase + path
}

func buildAuthorizeURL(authBase string, params url.Values) (string, error) {
	base := strings.TrimSpace(authBase)
	if base == "" {
		base = DefaultAuthBase
	}

	// 1. 去掉末尾可能存在的斜杠
	base = strings.TrimRight(base, "/")

	// 2. 检查 base 本身是否已经包含了 /oauth/authorize 后缀
	// 如果没有，手动补上标准的授权路由
	if !strings.HasSuffix(strings.ToLower(base), "/oauth/authorize") {
		base = base + "/oauth/authorize"
	}

	// 3. 核心修复：直接使用 params.Encode() 转化为标准的 QueryString
	queryString := params.Encode()

	// 4. 组装成最终的完整 URL
	finalURL := base + "?" + queryString

	return finalURL, nil
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
// OpenBrowser 跨平台打开浏览器（改用 PowerShell 彻底解决 Windows 特殊字符截断）
func OpenBrowser(targetURL string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		// 使用 PowerShell 发起，用单引号包裹整个 URL 防止解析
		cmd = "powershell"
		args = []string{"-NoProfile", "-Command", fmt.Sprintf("Start-Process '%s'", targetURL)}
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

	authURL, err := buildAuthorizeURL(authBase, params)
	if err != nil {
		return nil, err
	}

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

// WaitForOAuthCallback 启动本地服务器捕获回调（修复版）
func WaitForOAuthCallback(redirectURI string, timeout time.Duration) (*OAuthCallbackResult, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, err
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
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

	resultChan := make(chan *OAuthCallbackResult, 1)

	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    net.JoinHostPort(host, port),
		Handler: mux,
	}

	// 1. 将模板移到函数外部，作为包级别常量
	const callbackTemplate = `<!DOCTYPE html>
	<html lang="zh-CN">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>OAuth 认证结果</title>
		<style>
			:root {
				--bg-success: #e6f4ea;
				--primary-success: #137333;
				--bg-error: #fce8e6;
				--primary-error: #c5221f;
			}
			body { 
				font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Segoe UI", Roboto, sans-serif; 
				background-color: #f8f9fa; 
				display: flex; 
				justify-content: center; 
				align-items: center; 
				height: 100vh; 
				margin: 0;
				-webkit-font-smoothing: antialiased;
			}
			/* 融合 Apple 悬浮卡片与 Google 平面呼吸感 */
			.card { 
				background: #ffffff; 
				padding: 48px 32px; 
				border-radius: 24px; 
				box-shadow: 0 12px 40px rgba(0,0,0,0.04), 0 1px 2px rgba(0,0,0,0.02); 
				text-align: center; 
				max-width: 360px; 
				width: 85%%; 
				transition: transform 0.3s ease;
			}
			/* 状态图标：改用高阶几何圆形，抛弃粗糙的 Emoji */
			.icon-wrapper {
				width: 64px;
				height: 64px;
				border-radius: 50%%;
				display: flex;
				align-items: center;
				justify-content: center;
				margin: 0 auto 24px auto;
				position: relative;
			}
			/* 成功状态样式 (Google 绿) */
			.success .icon-wrapper {
				background-color: var(--bg-success);
				color: var(--primary-success);
			}
			.success .icon-wrapper::after {
				content: "✓";
				font-size: 28px;
				font-weight: bold;
			}
			/* 失败状态样式 (Google 红) */
			.error .icon-wrapper {
				background-color: var(--bg-error);
				color: var(--primary-error);
			}
			.error .icon-wrapper::after {
				content: "✕";
				font-size: 24px;
				font-weight: bold;
			}
			/* 字体排阶 */
			h2 { 
				margin: 0 0 12px 0; 
				color: #1f1f1f; 
				font-size: 22px;
				font-weight: 500;
				letter-spacing: -0.01em;
			}
			p { 
				color: #5f6368; 
				margin: 0 0 28px 0; 
				font-size: 14px; 
				line-height: 1.5;
			}
			/* 底部精致的微提示标签 */
			.badge {
				display: inline-flex;
				align-items: center;
				gap: 6px;
				padding: 6px 12px;
				background-color: #f1f3f4;
				border-radius: 100px;
				color: #70757a;
				font-size: 12px;
			}
			.badge .dot {
				width: 6px;
				height: 6px;
				background-color: #1a73e8;
				border-radius: 50%%;
				animation: blink 1.5s infinite ease-in-out;
			}
			@keyframes blink {
				0%%, 100%% { opacity: 0.4; }
				50%% { opacity: 1; }
			}
		</style>
	</head>
	<body>
		<div class="card %s">
			<div class="icon-wrapper"></div>
			<h2>%s</h2>
			<p>您的身份认证已安全完成。<br>页面数据已同步更新。</p>
			<div class="badge">
				<div class="dot"></div>
				<span>窗口将在 3 秒后自动关闭</span>
			</div>
		</div>
		<script>
			setTimeout(function() {
				window.close();
			}, 3000);
		</script>
	</body>
	</html>`

	// 修复点 1：屏蔽掉浏览器自带的 favicon 请求，防止干扰主路由
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc(expectedPath, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		res := &OAuthCallbackResult{
			Code:     query.Get("code"),
			State:    query.Get("state"),
			Error:    query.Get("error"),
			RawQuery: query,
		}

		// 渲染 HTML 界面
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if res.Error != "" {
			w.WriteHeader(http.StatusBadRequest)
			// 参数1: "error" 对应红圈样式； 参数2: 标题
			html := fmt.Sprintf(callbackTemplate, "error", "认证未成功")
			_, _ = w.Write([]byte(html))
		} else {
			w.WriteHeader(http.StatusOK)
			// 参数1: "success" 对应绿圈样式； 参数2: 标题
			html := fmt.Sprintf(callbackTemplate, "success", "认证成功")
			_, _ = w.Write([]byte(html))
		}
		// 修复点 2：不要在这里写 resultChan <- res，也不要直接 shutdown
		// 采用延时关闭策略，确保 HTTP 响应体完整输出到浏览器
		go func() {
			// 给浏览器 1 秒的时间来完全接收数据和渲染
			time.Sleep(1 * time.Second)
			resultChan <- res
			_ = server.Shutdown(context.Background())
		}()
	})

	// 异步启动服务器
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			resultChan <- nil
		}
	}()

	// 阻塞等待
	select {
	case res := <-resultChan:
		if res == nil {
			return nil, errors.New("failed to start local callback server")
		}
		return res, nil
	case <-time.After(timeout):
		_ = server.Shutdown(context.Background())
		return nil, errors.New("oauth callback timeout")
	}
}

// ExchangeAuthorizationCodeForToken 交换 Token
func ExchangeAuthorizationCodeForToken(clientID, clientSecret, code, codeVerifier, authBase string, useBasicAuth bool, timeout time.Duration) (*TokenResponse, error) {
	if strings.TrimSpace(clientID) == "" {
		return nil, errors.New("client_id is required")
	}
	if strings.TrimSpace(clientSecret) == "" {
		return nil, errors.New("client_secret is required")
	}
	if strings.TrimSpace(code) == "" {
		return nil, errors.New("authorization code is required")
	}
	if strings.TrimSpace(codeVerifier) == "" {
		return nil, errors.New("code_verifier is required")
	}

	if authBase == "" {
		authBase = DefaultAuthBase
	}

	tokenURL := joinOAuthEndpoint(authBase, "/oauth/token")

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

// RefreshAccessToken 使用 refresh_token 刷新访问令牌
func RefreshAccessToken(clientID, clientSecret, refreshToken, authBase string, useBasicAuth bool, timeout time.Duration) (*TokenResponse, error) {
	if strings.TrimSpace(clientID) == "" {
		return nil, errors.New("client_id is required")
	}
	if strings.TrimSpace(clientSecret) == "" {
		return nil, errors.New("client_secret is required")
	}
	if strings.TrimSpace(refreshToken) == "" {
		return nil, errors.New("refresh_token is required")
	}
	if authBase == "" {
		authBase = DefaultAuthBase
	}

	tokenURL := joinOAuthEndpoint(authBase, "/oauth/token")

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", strings.TrimSpace(refreshToken))

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	if useBasicAuth {
		req.SetBasicAuth(strings.TrimSpace(clientID), strings.TrimSpace(clientSecret))
	} else {
		form.Set("client_id", strings.TrimSpace(clientID))
		form.Set("client_secret", strings.TrimSpace(clientSecret))
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
		req.ContentLength = int64(len(form.Encode()))
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("refresh token failed: http %d, body=%s", resp.StatusCode, string(bodyBytes))
	}

	var tokenRes TokenResponse
	if err := json.Unmarshal(bodyBytes, &tokenRes); err != nil {
		return nil, fmt.Errorf("failed to parse token json: %w, raw=%s", err, string(bodyBytes))
	}

	return &tokenRes, nil
}

// RevokeToken 调用 /oauth/revoke 撤销访问令牌
func RevokeToken(token, authBase, tokenTypeHint, clientID, clientSecret string, useBasicAuth bool, timeout time.Duration) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("token is required")
	}
	if authBase == "" {
		authBase = DefaultAuthBase
	}
	if tokenTypeHint == "" {
		tokenTypeHint = "access_token"
	}

	revokeURL := joinOAuthEndpoint(authBase, "/oauth/revoke")
	form := url.Values{}
	form.Set("token", strings.TrimSpace(token))
	form.Set("token_type_hint", tokenTypeHint)

	req, err := http.NewRequest("POST", revokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}

	if useBasicAuth && strings.TrimSpace(clientID) != "" && strings.TrimSpace(clientSecret) != "" {
		req.SetBasicAuth(strings.TrimSpace(clientID), strings.TrimSpace(clientSecret))
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("revoke token failed: http %d, body=%s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// ExtractTokenFields 提取常用 Token 字段
func ExtractTokenFields(tokenResponse *TokenResponse) TokenFields {
	if tokenResponse == nil {
		return TokenFields{}
	}
	return TokenFields{
		AccessToken:  tokenResponse.AccessToken,
		RefreshToken: tokenResponse.RefreshToken,
		TokenType:    tokenResponse.TokenType,
		ExpiresIn:    tokenResponse.ExpiresIn,
		Scope:        tokenResponse.Scope,
	}
}

// OneClickOAuthStart 一键启动授权流程（可选等待回调）
func OneClickOAuthStart(clientID, authBase, redirectURI, scope string, autoOpenBrowser bool, waitCallback bool, timeout time.Duration) (*OAuthStartResult, error) {
	launch, err := PrepareOAuthLaunch(clientID, authBase, redirectURI, scope, "", "S256")
	if err != nil {
		return nil, err
	}

	if autoOpenBrowser {
		if err := OpenBrowser(launch.AuthURL); err != nil {
			return nil, fmt.Errorf("failed to open browser: %w", err)
		}
	}

	result := &OAuthStartResult{OAuthLaunchContext: *launch}
	if !waitCallback {
		return result, nil
	}

	callback, err := WaitForOAuthCallback(launch.RedirectURI, timeout)
	if err != nil {
		return nil, err
	}
	result.CallbackResult = callback
	if callback != nil {
		result.StateOK = callback.State == launch.State
	}

	return result, nil
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

// OneClickOAuthAuthorizeAndExchangeCompact 一键授权并返回精简结果
func OneClickOAuthAuthorizeAndExchangeCompact(clientID, clientSecret, authBase, redirectURI, scope string, autoOpenBrowser bool, timeout time.Duration, useBasicAuth bool) (*CompactResult, error) {
	full, err := OneClickOAuthAuthorizeAndExchange(clientID, clientSecret, authBase, redirectURI, scope, autoOpenBrowser, timeout, useBasicAuth)
	if err != nil {
		return nil, err
	}

	compact := &CompactResult{
		State:        full.State,
		CodeVerifier: full.CodeVerifier,
	}
	if full.CallbackResult != nil {
		compact.Code = full.CallbackResult.Code
	}
	if full.TokenResponse != nil {
		compact.AccessToken = full.TokenResponse.AccessToken
		compact.RefreshToken = full.TokenResponse.RefreshToken
		compact.TokenType = full.TokenResponse.TokenType
		compact.ExpiresIn = full.TokenResponse.ExpiresIn
		compact.Scope = full.TokenResponse.Scope
	}

	return compact, nil
}
