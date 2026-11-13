// Package auth implements one bounded, non-persistent desktop OIDC login.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	ProtocolVersion int      `json:"protocol_version"`
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	Scopes          []string `json:"scopes,omitempty"`
	ListenAddress   string   `json:"listen_address,omitempty"`
	CallbackPath    string   `json:"callback_path,omitempty"`
	TimeoutSeconds  int      `json:"timeout_seconds,omitempty"`
	HTTPTimeout     int      `json:"http_timeout_seconds,omitempty"`
	OpenBrowser     *bool    `json:"open_browser,omitempty"`
	AllowHTTP       bool     `json:"allow_insecure_loopback_http,omitempty"`
	IncludeTokens   bool     `json:"include_tokens,omitempty"`
	ParentPID       int      `json:"parent_pid,omitempty"`
	SuccessHTML     string   `json:"success_html,omitempty"`
	SuccessHTMLFile string   `json:"success_html_file,omitempty"`
	FailureHTML     string   `json:"failure_html,omitempty"`
	FailureHTMLFile string   `json:"failure_html_file,omitempty"`

	pagesLoaded bool
	successPage []byte
	failurePage []byte
}

// MaxPageBytes bounds each custom browser result page.
const MaxPageBytes = 65536

type Identity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type Tokens struct {
	IDToken     string    `json:"id_token"`
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type Result struct {
	Identity Identity `json:"identity"`
	Tokens   *Tokens  `json:"tokens,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

func fail(code, message string) error { return &Error{Code: code, Message: message} }

var callbackPath = regexp.MustCompile(`^/[a-zA-Z0-9/_.-]*$`)

func (c *Config) Validate() error {
	if c.ProtocolVersion != 1 {
		return fail("invalid_input", "protocol_version must be 1")
	}
	if c.ClientID == "" || strings.TrimSpace(c.ClientID) != c.ClientID {
		return fail("invalid_input", "client_id must be nonempty without surrounding whitespace")
	}
	if err := secureURL(c.Issuer, c.AllowHTTP); err != nil {
		return fail("invalid_input", "issuer must be an absolute HTTPS URL (HTTP requires explicit loopback allowance)")
	}
	u, _ := url.Parse(c.Issuer)
	if u.RawQuery != "" || u.Fragment != "" {
		return fail("invalid_input", "issuer must not contain a query or fragment")
	}
	if c.ListenAddress == "" {
		c.ListenAddress = "127.0.0.1:0"
	}
	host, port, err := net.SplitHostPort(c.ListenAddress)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fail("invalid_input", "listen_address must use a numeric loopback IP and port")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
		return fail("invalid_input", "listen_address has an invalid port")
	}
	if c.CallbackPath == "" {
		c.CallbackPath = "/callback"
	}
	if !callbackPath.MatchString(c.CallbackPath) || strings.Contains(c.CallbackPath, "//") || strings.Contains(c.CallbackPath, "/.") {
		return fail("invalid_input", "callback_path must be a simple absolute path")
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 180
	}
	if c.HTTPTimeout == 0 {
		c.HTTPTimeout = 15
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 900 || c.HTTPTimeout < 1 || c.HTTPTimeout > 60 || c.ParentPID < 0 || c.ParentPID > 2147483647 {
		return fail("invalid_input", "invalid timeout or parent_pid range")
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{oidc.ScopeOpenID}
	}
	found := false
	for _, s := range c.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n") || s == "offline_access" {
			return fail("invalid_input", "scopes must be nonempty individual values; offline_access is not supported")
		}
		found = found || s == oidc.ScopeOpenID
	}
	if !found {
		return fail("invalid_input", "scopes must include openid")
	}
	if !c.pagesLoaded {
		var err error
		if c.successPage, err = loadPage("success_html", c.SuccessHTML, c.SuccessHTMLFile); err != nil {
			return err
		}
		if c.failurePage, err = loadPage("failure_html", c.FailureHTML, c.FailureHTMLFile); err != nil {
			return err
		}
		c.pagesLoaded = true
	}
	return nil
}

// loadPage returns nil when the default plain-text page should be used.
func loadPage(key, inline, path string) ([]byte, error) {
	if inline != "" && path != "" {
		return nil, fail("invalid_input", key+" and "+key+"_file are mutually exclusive")
	}
	if inline != "" {
		if len(inline) > MaxPageBytes || !utf8.ValidString(inline) {
			return nil, fail("invalid_input", key+" must be UTF-8 of at most 65536 bytes")
		}
		return []byte(inline), nil
	}
	if path == "" {
		return nil, nil
	}
	// Messages never include the path, avoiding private filesystem details in output.
	invalid := fail("invalid_input", key+"_file must be an absolute path to a readable nonempty regular UTF-8 file of at most 65536 bytes")
	if !filepath.IsAbs(path) {
		return nil, invalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, invalid
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, invalid
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxPageBytes+1))
	if err != nil || len(b) == 0 || len(b) > MaxPageBytes || !utf8.Valid(b) {
		return nil, invalid
	}
	return b, nil
}

func secureURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return errors.New("invalid endpoint URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if allowHTTP && u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("insecure endpoint URL")
}

type guardedTransport struct {
	base      http.RoundTripper
	allowHTTP bool
	lifetime  context.Context
}

func (t guardedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := secureURL(r.URL.String(), t.allowHTTP); err != nil {
		return nil, err
	}
	// JWKS refreshes may detach caller cancellation; bind every request to this attempt too.
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(t.lifetime, cancel)
	cleanup := func() { stop(); cancel() }
	res, err := t.base.RoundTrip(r.Clone(ctx))
	if err != nil {
		cleanup()
		return nil, err
	}
	res.Body = &lifetimeBody{ReadCloser: res.Body, cleanup: cleanup}
	return res, nil
}

type lifetimeBody struct {
	io.ReadCloser
	cleanup func()
}

func (b *lifetimeBody) Close() error {
	defer b.cleanup()
	return b.ReadCloser.Close()
}

type Options struct {
	// Browser is injected so tests and headless callers never launch an OS browser.
	Browser func(context.Context, string) error
}

func randomValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type callback struct {
	code string
	err  error
}

func Run(ctx context.Context, c Config, opts Options) (*Result, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	result, err := run(ctx, c, opts)
	return completeAttempt(ctx, result, err)
}

func completeAttempt(ctx context.Context, result *Result, err error) (*Result, error) {
	// Cancellation wins until this completion gate, including over a ready identity.
	switch ctx.Err() {
	case context.DeadlineExceeded:
		return nil, fail("timeout", "authentication deadline exceeded")
	case context.Canceled:
		return nil, fail("cancelled", "authentication cancelled")
	}
	return result, err
}

func run(ctx context.Context, c Config, opts Options) (*Result, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = time.Duration(c.HTTPTimeout) * time.Second
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   time.Duration(c.HTTPTimeout) * time.Second,
		Transport: guardedTransport{base: transport, allowHTTP: c.AllowHTTP, lifetime: ctx},
		// Discovery, token and JWKS URLs must work directly; never forward credentials on redirects.
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not allowed") },
	}
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, fail("discovery_failed", "OIDC discovery failed")
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if provider.Claims(&metadata) != nil || secureURL(metadata.JWKS, c.AllowHTTP) != nil ||
		secureURL(provider.Endpoint().AuthURL, c.AllowHTTP) != nil ||
		secureURL(provider.Endpoint().TokenURL, c.AllowHTTP) != nil {
		return nil, fail("discovery_failed", "provider advertised an invalid or insecure endpoint")
	}
	listener, err := net.Listen("tcp", c.ListenAddress)
	if err != nil {
		return nil, fail("listener_failed", "could not bind exclusive loopback listener")
	}
	defer listener.Close()
	state, err := randomValue()
	if err != nil {
		return nil, fail("internal_error", "secure randomness unavailable")
	}
	nonce, err := randomValue()
	if err != nil {
		return nil, fail("internal_error", "secure randomness unavailable")
	}
	verifier, err := randomValue()
	if err != nil {
		return nil, fail("internal_error", "secure randomness unavailable")
	}
	redirect := "http://" + listener.Addr().String() + c.CallbackPath
	oauth := oauth2.Config{ClientID: c.ClientID, Endpoint: provider.Endpoint(), RedirectURL: redirect, Scopes: c.Scopes}
	oauth.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	pending := make(chan callback, 1)
	outcome := make(chan bool, 1)
	written := make(chan struct{})
	var received atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet || r.URL.Path != c.CallbackPath || r.Host != listener.Addr().String() {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
		if len(q["iss"]) > 1 || (len(q["iss"]) == 1 && q.Get("iss") != c.Issuer) {
			http.Error(w, "Invalid issuer", http.StatusBadRequest)
			return
		}
		cb := callback{}
		switch {
		case len(q["error"]) == 1 && q.Get("error") != "" && len(q["code"]) == 0:
			cb.err = fail("oauth_error", "provider rejected authentication")
		case len(q["code"]) == 1 && q.Get("code") != "" && len(q["error"]) == 0:
			cb.code = q.Get("code")
		default:
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
		if !received.CompareAndSwap(false, true) {
			http.Error(w, "Already received", http.StatusConflict)
			return
		}
		defer close(written)
		// Hold the response until the outcome is known; bound it by the attempt deadline.
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Time{})
		if deadline, ok := ctx.Deadline(); ok {
			_ = rc.SetWriteDeadline(deadline.Add(5 * time.Second))
		}
		pending <- cb
		ok := false
		select {
		case ok = <-outcome:
		case <-ctx.Done():
		}
		writePage(w, ok, c)
		_ = rc.Flush()
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	defer server.Close()
	defer func() {
		// Let the accepted callback finish writing its result page before closing the server.
		if received.Load() {
			select {
			case <-written:
			case <-time.After(2 * time.Second):
			}
		}
	}()
	authURL := oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	if opts.Browser == nil || opts.Browser(ctx, authURL) != nil {
		return nil, fail("browser_failed", "could not launch or report authorization URL")
	}
	var cb callback
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-serverErrors:
		return nil, fail("listener_failed", "loopback listener stopped unexpectedly")
	case cb = <-pending:
	}
	result, err := verify(ctx, c, provider, &oauth, cb, verifier, nonce)
	outcome <- err == nil && ctx.Err() == nil
	return result, err
}

func writePage(w http.ResponseWriter, ok bool, c Config) {
	page := c.failurePage
	if ok {
		page = c.successPage
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if page == nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		page = []byte("Authentication failed. You may close this window.\n")
		if ok {
			page = []byte("Authentication succeeded. You may close this window.\n")
		}
	} else {
		// Custom pages may use inline styles and data: images only: no scripts, forms or network fetches.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(page)))
	w.Write(page)
}

func verify(ctx context.Context, c Config, provider *oidc.Provider, oauth *oauth2.Config, cb callback, verifier, nonce string) (*Result, error) {
	if cb.err != nil {
		return nil, cb.err
	}
	token, err := oauth.Exchange(ctx, cb.code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fail("token_exchange_failed", "authorization code exchange failed")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, fail("token_invalid", "provider did not return an ID token")
	}
	id, err := provider.Verifier(&oidc.Config{
		ClientID:             c.ClientID,
		SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"},
	}).Verify(ctx, raw)
	if err != nil {
		return nil, fail("token_invalid", "ID token verification failed")
	}
	if id.Subject == "" || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(nonce)) != 1 {
		return nil, fail("token_invalid", "ID token subject or nonce is invalid")
	}
	var claims struct {
		IssuedAt  int64  `json:"iat"`
		NotBefore int64  `json:"nbf"`
		AZP       string `json:"azp"`
	}
	if id.Claims(&claims) != nil || claims.IssuedAt <= 0 || claims.IssuedAt > id.Expiry.Unix() || claims.IssuedAt > time.Now().Add(time.Minute).Unix() ||
		claims.NotBefore > time.Now().Add(time.Minute).Unix() ||
		(len(id.Audience) > 1 && claims.AZP != c.ClientID) || (claims.AZP != "" && claims.AZP != c.ClientID) {
		return nil, fail("token_invalid", "ID token time or authorized party is invalid")
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		return nil, fail("token_invalid", "access token hash verification failed")
	}
	result := &Result{Identity: Identity{Issuer: id.Issuer, Subject: id.Subject}}
	if c.IncludeTokens {
		result.Tokens = &Tokens{IDToken: raw, AccessToken: token.AccessToken, TokenType: token.TokenType, ExpiresAt: token.Expiry}
	}
	return result, nil
}
