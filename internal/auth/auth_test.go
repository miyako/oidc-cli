package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type issuerFixture struct {
	server                     *httptest.Server
	key                        *rsa.PrivateKey
	otherKey                   *rsa.PrivateKey
	mu                         sync.Mutex
	nonce, challenge, redirect string
	mode                       string
	jwksStarted                chan struct{}
	jwksCancelled              chan struct{}
	pages                      chan resultPage
}

type resultPage struct {
	status      int
	contentType string
	csp         string
	body        string
	err         error
}

func newIssuer(t *testing.T, mode string) *issuerFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &issuerFixture{key: key, otherKey: other, mode: mode, pages: make(chan resultPage, 8)}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *issuerFixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		if f.mode == "discovery_redirect" {
			http.Redirect(w, r, f.server.URL+"/discovery", http.StatusFound)
			return
		}
		issuer := f.server.URL
		authURL := issuer + "/authorize"
		if f.mode == "discovery_issuer" {
			issuer += "/wrong"
		}
		if f.mode == "insecure_endpoint" {
			authURL = "http://example.com/authorize"
		}
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": authURL,
			"token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case "/jwks":
		if f.mode == "jwks_wait" {
			close(f.jwksStarted)
			select {
			case <-r.Context().Done():
				close(f.jwksCancelled)
			case <-time.After(3 * time.Second):
			}
			return
		}
		if f.mode == "jwks_redirect" {
			http.Redirect(w, r, f.server.URL+"/keys", http.StatusFound)
			return
		}
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
	case "/token":
		if f.mode == "token_redirect" {
			http.Redirect(w, r, f.server.URL+"/other-token", http.StatusTemporaryRedirect)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		f.mu.Lock()
		nonce, challenge, redirect := f.nonce, f.challenge, f.redirect
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge ||
			r.Form.Get("redirect_uri") != redirect || r.Form.Get("client_id") != "desktop" ||
			r.Form.Get("code") != "valid-code" || r.Form.Get("grant_type") != "authorization_code" ||
			r.Form.Get("client_secret") != "" || r.Header.Get("Authorization") != "" {
			http.Error(w, "invalid exchange", 400)
			return
		}
		if f.mode == "exchange_error" {
			http.Error(w, "sensitive provider diagnostic", 400)
			return
		}
		if f.mode == "http_timeout" {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(1500 * time.Millisecond):
			}
		}
		now := time.Now()
		claims := map[string]any{"iss": f.server.URL, "sub": "user-123", "aud": "desktop",
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": nonce}
		key := f.key
		switch f.mode {
		case "nonce":
			claims["nonce"] = "wrong"
		case "audience":
			claims["aud"] = "wrong"
		case "issuer":
			claims["iss"] = "https://wrong.example"
		case "expired":
			claims["exp"] = now.Add(-time.Minute).Unix()
		case "future_iat":
			claims["iat"] = now.Add(time.Hour).Unix()
		case "future_nbf":
			claims["nbf"] = now.Add(time.Hour).Unix()
		case "missing_exp":
			delete(claims, "exp")
		case "missing_iat":
			delete(claims, "iat")
		case "missing_sub":
			delete(claims, "sub")
		case "signature":
			key = f.otherKey
		case "multiple_aud":
			claims["aud"] = []string{"desktop", "other"}
		case "azp":
			claims["azp"] = "other"
		case "at_hash":
			claims["at_hash"] = "wrong"
		case "multiple_aud_valid":
			claims["aud"] = []string{"desktop", "other"}
			claims["azp"] = "desktop"
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "test"}}, nil)
		if err != nil {
			http.Error(w, "sign failed", 500)
			return
		}
		data, _ := json.Marshal(claims)
		obj, _ := signer.Sign(data)
		raw, _ := obj.CompactSerialize()
		if f.mode == "algorithm" {
			raw = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(data) + "."
		}
		response := map[string]any{"access_token": "sensitive-access-token", "token_type": "Bearer", "expires_in": 60, "id_token": raw, "refresh_token": "never-return-this"}
		if f.mode == "missing_token" {
			delete(response, "id_token")
		}
		json.NewEncoder(w).Encode(response)
	default:
		http.NotFound(w, r)
	}
}

func (f *issuerFixture) config() Config {
	return Config{ProtocolVersion: 1, Issuer: f.server.URL, ClientID: "desktop", AllowHTTP: true, TimeoutSeconds: 3, HTTPTimeout: 1}
}

func (f *issuerFixture) browser(t *testing.T, mutate func(url.Values)) func(context.Context, string) error {
	t.Helper()
	return func(ctx context.Context, target string) error {
		u, err := url.Parse(target)
		if err != nil {
			return err
		}
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("scope") != "openid" {
			t.Errorf("bad authorization request: %v", q)
		}
		for _, k := range []string{"state", "nonce", "code_challenge"} {
			if len(q.Get(k)) != 43 {
				t.Errorf("%s not 256-bit base64url", k)
			}
		}
		f.mu.Lock()
		f.nonce, f.challenge, f.redirect = q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")
		f.mu.Unlock()
		cb, _ := url.Parse(q.Get("redirect_uri"))
		values := url.Values{"state": {q.Get("state")}, "code": {"valid-code"}, "iss": {f.server.URL}}
		if mutate != nil {
			mutate(values)
		}
		cb.RawQuery = values.Encode()
		// Like a real browser, navigate asynchronously: the result page arrives after the outcome.
		go func() {
			res, err := http.Get(cb.String())
			if err != nil {
				f.pages <- resultPage{err: err}
				return
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			f.pages <- resultPage{res.StatusCode, res.Header.Get("Content-Type"), res.Header.Get("Content-Security-Policy"), string(body), err}
		}()
		return nil
	}
}

func (f *issuerFixture) page(t *testing.T) resultPage {
	t.Helper()
	select {
	case p := <-f.pages:
		if p.err != nil || p.status != 200 {
			t.Fatalf("callback page: %+v %v", p, p.err)
		}
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no callback page")
	}
	return resultPage{}
}

func errorCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func TestAuthentication(t *testing.T) {
	f := newIssuer(t, "")
	for _, include := range []bool{false, true} {
		c := f.config()
		c.IncludeTokens = include
		r, err := Run(context.Background(), c, Options{Browser: f.browser(t, nil)})
		if err != nil {
			t.Fatal(err)
		}
		if r.Identity.Issuer != f.server.URL || r.Identity.Subject != "user-123" {
			t.Fatalf("wrong identity: %+v", r)
		}
		data, _ := json.Marshal(r)
		if include {
			if r.Tokens == nil || r.Tokens.IDToken == "" || r.Tokens.AccessToken == "" {
				t.Fatal("missing explicit tokens")
			}
		} else if strings.Contains(string(data), "token") {
			t.Fatalf("default leaks tokens: %s", data)
		}
		if strings.Contains(string(data), "never-return-this") {
			t.Fatal("refresh token leaked")
		}
	}
}

func TestInvalidTokens(t *testing.T) {
	for _, mode := range []string{"nonce", "audience", "issuer", "expired", "future_iat", "future_nbf", "missing_exp", "missing_iat", "missing_sub", "signature", "multiple_aud", "azp", "at_hash", "algorithm", "missing_token", "jwks_redirect"} {
		t.Run(mode, func(t *testing.T) {
			f := newIssuer(t, mode)
			_, err := Run(context.Background(), f.config(), Options{Browser: f.browser(t, nil)})
			errorCode(t, err, "token_invalid")
		})
	}
}

func TestMultipleAudienceAuthorizedParty(t *testing.T) {
	f := newIssuer(t, "multiple_aud_valid")
	if _, err := Run(context.Background(), f.config(), Options{Browser: f.browser(t, nil)}); err != nil {
		t.Fatal(err)
	}
}

func TestUnrelatedCallbacksDoNotConsumeAttempt(t *testing.T) {
	f := newIssuer(t, "")
	browser := f.browser(t, nil)
	_, err := Run(context.Background(), f.config(), Options{Browser: func(ctx context.Context, target string) error {
		u, _ := url.Parse(target)
		redirect := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")
		for _, query := range []string{
			"state=wrong&code=valid-code", "state=" + state + "&code=one&code=two",
			"state=" + state, "state=" + state + "&code=valid-code&iss=wrong",
			"state=" + state + "&code=valid-code&error=access_denied", "state=" + state + "&code=%zz",
			"state=" + state + "&state=" + state + "&code=valid-code",
		} {
			req, _ := http.NewRequestWithContext(ctx, "GET", redirect+"?"+query, nil)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			res.Body.Close()
			if res.StatusCode != 400 {
				t.Errorf("malformed callback accepted: %s", query)
			}
		}
		for _, method := range []string{"POST", "OPTIONS"} {
			req, _ := http.NewRequestWithContext(ctx, method, redirect, nil)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			res.Body.Close()
			if res.StatusCode != 404 {
				t.Errorf("method accepted: %s", method)
			}
		}
		res, err := http.Get(strings.TrimSuffix(redirect, "/callback") + "/favicon.ico")
		if err != nil {
			return err
		}
		res.Body.Close()
		if res.StatusCode != 404 {
			t.Error("unrelated path accepted")
		}
		return browser(ctx, target)
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOAuthError(t *testing.T) {
	f := newIssuer(t, "")
	_, err := Run(context.Background(), f.config(), Options{Browser: f.browser(t, func(q url.Values) {
		q.Del("code")
		q.Set("error", "access_denied")
		q.Set("error_description", "secret")
	})})
	errorCode(t, err, "oauth_error")
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("provider diagnostic leaked")
	}
}

func TestDeadlineAndCancellation(t *testing.T) {
	f := newIssuer(t, "")
	c := f.config()
	c.TimeoutSeconds = 1
	_, err := Run(context.Background(), c, Options{Browser: func(context.Context, string) error { return nil }})
	errorCode(t, err, "timeout")
	ctx, cancel := context.WithCancel(context.Background())
	_, err = Run(ctx, f.config(), Options{Browser: func(context.Context, string) error { cancel(); return nil }})
	errorCode(t, err, "cancelled")
}

func TestOperationalFailures(t *testing.T) {
	for mode, want := range map[string]string{
		"discovery_issuer": "discovery_failed", "insecure_endpoint": "discovery_failed",
		"exchange_error": "token_exchange_failed", "http_timeout": "token_exchange_failed",
		"discovery_redirect": "discovery_failed", "token_redirect": "token_exchange_failed",
	} {
		t.Run(mode, func(t *testing.T) {
			f := newIssuer(t, mode)
			_, err := Run(context.Background(), f.config(), Options{Browser: f.browser(t, nil)})
			errorCode(t, err, want)
		})
	}

	f := newIssuer(t, "")
	_, err := Run(context.Background(), f.config(), Options{Browser: func(context.Context, string) error { return errors.New("sensitive path") }})
	errorCode(t, err, "browser_failed")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c := f.config()
	c.ListenAddress = l.Addr().String()
	_, err = Run(context.Background(), c, Options{Browser: f.browser(t, nil)})
	errorCode(t, err, "listener_failed")
}

func TestExactCustomCallbackPath(t *testing.T) {
	f := newIssuer(t, "")
	c := f.config()
	c.CallbackPath = "/oidc/return"
	result, err := Run(context.Background(), c, Options{Browser: f.browser(t, nil)})
	if err != nil || result == nil {
		t.Fatalf("custom callback failed: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	redirect, err := url.Parse(f.redirect)
	if err != nil || redirect.Path != c.CallbackPath || redirect.Port() == "0" || redirect.Hostname() != "127.0.0.1" {
		t.Fatalf("incorrect callback: %s", f.redirect)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, modify := range map[string]func(*Config){
		"version":            func(c *Config) { c.ProtocolVersion = 2 },
		"secret-ish-client":  func(c *Config) { c.ClientID = "" },
		"production-http":    func(c *Config) { c.AllowHTTP = false },
		"nonlocal-http":      func(c *Config) { c.Issuer = "http://example.com"; c.AllowHTTP = true },
		"localhost-http":     func(c *Config) { c.Issuer = "http://localhost:8080"; c.AllowHTTP = true },
		"credentials":        func(c *Config) { c.Issuer = "https://user:pass@example.com" },
		"all-interfaces":     func(c *Config) { c.ListenAddress = "0.0.0.0:0" },
		"hostname":           func(c *Config) { c.ListenAddress = "localhost:0" },
		"service-port":       func(c *Config) { c.ListenAddress = "127.0.0.1:http" },
		"callback-query":     func(c *Config) { c.CallbackPath = "/callback?foo" },
		"callback-traversal": func(c *Config) { c.CallbackPath = "/../callback" },
		"deadline":           func(c *Config) { c.TimeoutSeconds = 901 },
		"http-timeout":       func(c *Config) { c.HTTPTimeout = 61 },
		"offline":            func(c *Config) { c.Scopes = []string{"openid", "offline_access"} },
		"missing-openid":     func(c *Config) { c.Scopes = []string{"email"} },
		"parent":             func(c *Config) { c.ParentPID = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := Config{ProtocolVersion: 1, Issuer: "http://127.0.0.1:8080/realm", ClientID: "desktop", AllowHTTP: true}
			modify(&c)
			errorCode(t, c.Validate(), "invalid_input")
		})
	}
}

func TestListenerClosedAfterCancellation(t *testing.T) {
	f := newIssuer(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	var address string
	_, err := Run(ctx, f.config(), Options{Browser: func(_ context.Context, target string) error {
		u, _ := url.Parse(target)
		redirect, _ := url.Parse(u.Query().Get("redirect_uri"))
		address = redirect.Host
		cancel()
		return nil
	}})
	errorCode(t, err, "cancelled")
	conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("listener survived cancellation")
	}
}

func TestJWKSRequestCancelledWithAttempt(t *testing.T) {
	for _, mode := range []string{"cancelled", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := newIssuer(t, "jwks_wait")
			f.jwksStarted = make(chan struct{})
			f.jwksCancelled = make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			c := f.config()
			c.HTTPTimeout = 5
			if mode == "timeout" {
				c.TimeoutSeconds = 1
			}
			go func() {
				_, err := Run(ctx, c, Options{Browser: f.browser(t, nil)})
				done <- err
			}()
			select {
			case <-f.jwksStarted:
			case <-time.After(2 * time.Second):
				t.Fatal("JWKS request did not start")
			}
			if mode == "cancelled" {
				cancel()
			}
			errorCode(t, <-done, mode)
			select {
			case <-f.jwksCancelled:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("JWKS HTTP request survived attempt completion")
			}
		})
	}
}

func TestCompletionGateCancellationPriority(t *testing.T) {
	identity := &Result{Identity: Identity{Issuer: "https://example.com", Subject: "user"}}
	operationError := fail("token_invalid", "ID token verification failed")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, tc := range []struct {
		ctx  context.Context
		code string
	}{{cancelled, "cancelled"}, {expired, "timeout"}} {
		for _, underlying := range []error{nil, operationError} {
			result, err := completeAttempt(tc.ctx, identity, underlying)
			if result != nil {
				t.Fatal("cancelled attempt exposed a ready identity")
			}
			errorCode(t, err, tc.code)
		}
	}
	result, err := completeAttempt(context.Background(), identity, nil)
	if result != identity || err != nil {
		t.Fatal("active attempt lost its verified result")
	}
	result, err = completeAttempt(context.Background(), nil, operationError)
	if result != nil || err != operationError {
		t.Fatal("active attempt lost its operation error")
	}
}

func TestResultPages(t *testing.T) {
	strict := "default-src 'none'; frame-ancestors 'none'"
	f := newIssuer(t, "")
	if _, err := Run(context.Background(), f.config(), Options{Browser: f.browser(t, nil)}); err != nil {
		t.Fatal(err)
	}
	if p := f.page(t); !strings.Contains(p.body, "Authentication succeeded") || p.csp != strict || !strings.HasPrefix(p.contentType, "text/plain") {
		t.Fatalf("default success page: %+v", p)
	}
	_, err := Run(context.Background(), f.config(), Options{Browser: f.browser(t, func(q url.Values) {
		q.Del("code")
		q.Set("error", "access_denied")
		q.Set("error_description", "secret")
	})})
	errorCode(t, err, "oauth_error")
	if p := f.page(t); !strings.Contains(p.body, "Authentication failed") || strings.Contains(p.body, "secret") || p.csp != strict {
		t.Fatalf("default failure page: %+v", p)
	}

	failure := filepath.Join(t.TempDir(), "failure.html")
	if err := os.WriteFile(failure, []byte("<h1>Sign-in failed</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}
	custom := func(f *issuerFixture) Config {
		c := f.config()
		c.SuccessHTML = "<style>h1{color:green}</style><h1>Signed in</h1>"
		c.FailureHTMLFile = failure
		return c
	}
	if _, err := Run(context.Background(), custom(f), Options{Browser: f.browser(t, nil)}); err != nil {
		t.Fatal(err)
	}
	p := f.page(t)
	if p.body != "<style>h1{color:green}</style><h1>Signed in</h1>" || !strings.HasPrefix(p.contentType, "text/html") ||
		!strings.Contains(p.csp, "style-src 'unsafe-inline'") || strings.Contains(p.csp, "script-src") {
		t.Fatalf("custom success page: %+v", p)
	}
	// Verification failures happen after the callback; the page must still report failure.
	bad := newIssuer(t, "nonce")
	_, err = Run(context.Background(), custom(bad), Options{Browser: bad.browser(t, nil)})
	errorCode(t, err, "token_invalid")
	if p := bad.page(t); p.body != "<h1>Sign-in failed</h1>" {
		t.Fatalf("custom failure page: %+v", p)
	}
}

func TestResultPageValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := write("ok.html", []byte("<p>ok</p>"))
	for name, modify := range map[string]func(*Config){
		"both":        func(c *Config) { c.SuccessHTML = "<p>ok</p>"; c.SuccessHTMLFile = valid },
		"relative":    func(c *Config) { c.FailureHTMLFile = "ok.html" },
		"missing":     func(c *Config) { c.SuccessHTMLFile = filepath.Join(dir, "missing.html") },
		"directory":   func(c *Config) { c.SuccessHTMLFile = dir },
		"empty-file":  func(c *Config) { c.SuccessHTMLFile = write("empty.html", nil) },
		"large-file":  func(c *Config) { c.FailureHTMLFile = write("large.html", make([]byte, MaxPageBytes+1)) },
		"binary-file": func(c *Config) { c.FailureHTMLFile = write("bad.html", []byte{0xff, 0xfe}) },
		"large":       func(c *Config) { c.FailureHTML = strings.Repeat("a", MaxPageBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			c := Config{ProtocolVersion: 1, Issuer: "http://127.0.0.1:8080/realm", ClientID: "desktop", AllowHTTP: true}
			modify(&c)
			err := c.Validate()
			errorCode(t, err, "invalid_input")
			if strings.Contains(err.Error(), dir) {
				t.Fatal("path leaked")
			}
		})
	}
	c := Config{ProtocolVersion: 1, Issuer: "http://127.0.0.1:8080/realm", ClientID: "desktop", AllowHTTP: true, SuccessHTMLFile: valid}
	if err := c.Validate(); err != nil || string(c.successPage) != "<p>ok</p>" || c.failurePage != nil {
		t.Fatalf("valid page: %v", err)
	}
}
