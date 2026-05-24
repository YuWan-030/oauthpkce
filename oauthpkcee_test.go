package oauthpkce

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 1. 测试 PKCE 验证码和挑战码的生成逻辑
func TestPKCEGeneration(t *testing.T) {
	// 测试长度限制边界
	_, err := GeneratePKCEVerifier(42)
	if err == nil {
		t.Error("预期长度小于 43 时报错，但实际没有报错")
	}

	// 测试正常生成
	verifier, err := GeneratePKCEVerifier(64)
	if err != nil {
		t.Fatalf("生成 Verifier 失败: %v", err)
	}
	if len(verifier) != 64 {
		t.Errorf("预期长度为 64，实际长度为 %d", len(verifier))
	}

	// 测试 S256 挑战码生成
	challenge, err := GeneratePKCEChallenge(verifier, "S256")
	if err != nil {
		t.Fatalf("生成 Challenge 失败: %v", err)
	}
	if len(challenge) == 0 {
		t.Error("生成的 Challenge 不能为空")
	}

	// 测试 PLAIN 模式
	plainChallenge, err := GeneratePKCEChallenge(verifier, "PLAIN")
	if err != nil {
		t.Fatalf("PLAIN 模式生成失败: %v", err)
	}
	if plainChallenge != verifier {
		t.Error("PLAIN 模式下 Challenge 应与 Verifier 完全一致")
	}
}

// 2. 测试授权 URL 的参数组装
func TestPrepareOAuthLaunch(t *testing.T) {
	clientID := "test-client"
	authBase := "https://login.example.com"
	redirectURI := "http://127.0.0.1:8765/callback"
	scope := "user_info"

	ctx, err := PrepareOAuthLaunch(clientID, authBase, redirectURI, scope, "custom-state", "S256")
	if err != nil {
		t.Fatalf("PrepareOAuthLaunch 失败: %v", err)
	}

	// 验证返回的上下文
	if ctx.ClientID != clientID {
		t.Errorf("ClientID 不匹配: 期望 %s, 实际 %s", clientID, ctx.ClientID)
	}
	if ctx.State != "custom-state" {
		t.Errorf("State 不匹配")
	}

	// 验证生成的 URL 是否包含核心参数
	if !strings.HasPrefix(ctx.AuthURL, authBase) {
		t.Errorf("URL 前缀错误: %s", ctx.AuthURL)
	}
	if !strings.Contains(ctx.AuthURL, "client_id=test-client") {
		t.Error("URL 中未包含 client_id")
	}
	if !strings.Contains(ctx.AuthURL, "code_challenge_method=S256") {
		t.Error("URL 中未包含 code_challenge_method")
	}
}

// 3. 模拟真实的 Token 交换请求（使用 httptest 模拟授权服务器）
func TestExchangeAuthorizationCodeForToken(t *testing.T) {
	// 创建一个模拟的 OAuth2 Token 服务器
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查请求路径
		if r.URL.Path != "/oauth/token" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// 检查 Basic Auth
		username, password, ok := r.BasicAuth()
		if !ok || username != "my-client" || password != "my-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}

		// 检查 Form 表单参数
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "mock-code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}

		// 返回模拟的成功 JSON
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"access_token": "mock-access-token-12345",
			"refresh_token": "mock-refresh-token-67890",
			"token_type": "Bearer",
			"expires_in": 3600,
			"scope": "read"
		}`))
	}))
	defer mockServer.Close()

	// 调用我们的函数，将 authBase 指向模拟服务器的 URL
	tokenRes, err := ExchangeAuthorizationCodeForToken(
		"my-client",
		"my-secret",
		"mock-code",
		"mock-verifier",
		mockServer.URL, // 动态生成的 mock 服务器地址
		true,           // 使用 Basic Auth
		5*time.Second,
	)

	if err != nil {
		t.Fatalf("交换 Token 失败: %v", err)
	}

	// 断言结果
	if tokenRes.AccessToken != "mock-access-token-12345" {
		t.Errorf("Access Token 不匹配，拿到的是: %s", tokenRes.AccessToken)
	}
	if tokenRes.ExpiresIn != 3600 {
		t.Errorf("过期时间不匹配")
	}
}
