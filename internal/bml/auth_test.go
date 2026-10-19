package bml

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testOTP         = "123456"
	testBusinessOTP = "654321"
	personalID      = "PERSONAL-1"
	businessID      = "BUSINESS-1"
	// inertiaID answers profile selection the way Inertia clients see it.
	inertiaID = "INERTIA-1"
)

// fakeBML imitates the parts of BML's login flow the client relies on.
type fakeBML struct {
	t         *testing.T
	callback  string
	profiles  int // 1 = single profile, 2 = personal + business
	mu        sync.Mutex
	challenge string
	state     string
	sentVia   []string
}

func newFakeBML(t *testing.T, profiles int) (*fakeBML, *Client) {
	t.Helper()
	f := &fakeBML{t: t, profiles: profiles}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{BaseURL: srv.URL, DeviceID: "DEVICE-1"})
	if err != nil {
		t.Fatal(err)
	}
	f.callback = c.cfg.CallbackURI()
	return f, c
}

func (f *fakeBML) page(w http.ResponseWriter, props map[string]any) {
	data, _ := json.Marshal(map[string]any{"component": "X", "props": props})
	w.Header().Set("Content-Type", "text/html")
	gz := gzip.NewWriter(w)
	w.Header().Set("Content-Encoding", "gzip")
	_, _ = gz.Write([]byte(`<html><body><div id="app" data-page="` + html.EscapeString(string(data)) + `"></div></body></html>`))
	_ = gz.Close()
}

func (f *fakeBML) redirect(w http.ResponseWriter, to string) {
	w.Header().Set("Location", to)
	w.WriteHeader(http.StatusFound)
}

func (f *fakeBML) issueCode(w http.ResponseWriter) {
	f.redirect(w, f.callback+"?code=AUTHCODE&state="+f.state)
}

func (f *fakeBML) loggedIn(r *http.Request) bool {
	c, err := r.Cookie("session")
	return err == nil && c.Value == "ok"
}

var channels = []map[string]string{
	{"channel": "mobile", "description": "Mobile", "masked": "96****2238"},
	{"channel": "authenticator", "description": "Authenticator", "masked": "GA502170"},
}

func (f *fakeBML) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	path := strings.TrimPrefix(r.URL.Path, "/internetbanking")

	if path != "/oauth/token" && r.Header.Get("x-app-version") == "" {
		f.t.Errorf("%s %s: missing mobile app headers", r.Method, r.URL.Path)
	}

	switch {
	case path == "/oauth/authorize" && r.URL.Query().Get("client_id") != "":
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || r.Header.Get("Device-ID") != "DEVICE-1" {
			f.t.Errorf("authorize: bad request %v", q)
		}
		f.mu.Lock()
		f.challenge, f.state = q.Get("code_challenge"), q.Get("state")
		f.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "pending", Path: "/"})
		f.redirect(w, "/internetbanking/web/login")

	case path == "/oauth/authorize": // resumed after 2FA/profile selection
		f.issueCode(w)

	case path == "/web/login" && r.Method == http.MethodPost:
		if r.Form.Get("username") != "user" || r.Form.Get("password") != "pass" {
			f.redirect(w, "/internetbanking/web/login?failed=1")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
		f.redirect(w, "/internetbanking/web/login/2fa")

	case path == "/web/login" && r.Method == http.MethodGet:
		f.page(w, map[string]any{"channels": []any{}, "errors": map[string]any{"username": "These credentials do not match our records."}})

	case path == "/web/login/2fa" && r.Method == http.MethodGet:
		f.page(w, map[string]any{"channels": channels})

	case path == "/web/login/2fa" && r.Method == http.MethodPost:
		if !f.loggedIn(r) {
			f.t.Error("2fa: session cookie not sent")
		}
		code, ch := r.Form.Get("code"), r.Form.Get("channel")
		switch {
		case code == "":
			f.mu.Lock()
			f.sentVia = append(f.sentVia, ch)
			f.mu.Unlock()
			f.page(w, map[string]any{"channels": channels})
		case code != testOTP:
			f.page(w, map[string]any{"channels": channels, "flash": map[string]any{"message": "Invalid OTP"}})
		case f.profiles == 1:
			f.redirect(w, "/internetbanking/oauth/authorize?resume=1")
		default:
			f.redirect(w, "/internetbanking/web/profile")
		}

	case path == "/web/profile":
		f.page(w, map[string]any{"profiles": []map[string]any{
			{"name": "Personal", "profile_id": personalID, "profile": map[string]any{"customer_type": "Individual", "profile_type": "default"}},
			{"name": "Acme Pvt Ltd", "profile_id": businessID, "profile": map[string]any{"customer_type": "Business", "profile_type": "parent"}},
		}})

	case path == "/web/profile/"+personalID:
		f.redirect(w, "/internetbanking/oauth/authorize?resume=1")

	case path == "/web/profile/"+inertiaID:
		w.Header().Set("X-Inertia-Location", "/internetbanking/oauth/authorize?resume=1")
		w.WriteHeader(http.StatusConflict)

	case path == "/web/profile/"+businessID:
		f.page(w, map[string]any{"channels": []map[string]string{
			{"channel": "Mobile", "description": "Mobile", "masked": "96****2238"},
			{"channel": "Authenticator", "description": "Authenticator", "masked": ""},
		}})

	case path == "/web/profile/2fa/business":
		switch r.Form.Get("code") {
		case "":
			f.page(w, map[string]any{"channels": []map[string]string{{"channel": "Mobile", "description": "Mobile"}}})
		case testBusinessOTP:
			f.issueCode(w)
		default:
			f.page(w, map[string]any{"flash": map[string]any{"message": "Invalid business OTP"}})
		}

	case path == "/oauth/token":
		f.token(w, r)

	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	}
}

func (f *fakeBML) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		f.mu.Lock()
		challenge := f.challenge
		f.mu.Unlock()
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || r.Form.Get("code") != "AUTHCODE" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3600,"access_token":"ACCESS","refresh_token":"REFRESH"}`))
	case "refresh_token":
		if r.Form.Get("refresh_token") != "REFRESH" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":"7200","access_token":"ACCESS2","refresh_token":"REFRESH2"}`))
	}
}

func checkTokens(t *testing.T, tok *Tokens, access string, ttl time.Duration) {
	t.Helper()
	if tok == nil || tok.AccessToken != access {
		t.Fatalf("tokens = %+v, want access token %q", tok, access)
	}
	if d := time.Until(tok.ExpiresAt); d < ttl-time.Minute || d > ttl {
		t.Errorf("expires at %v, want about %v from now", tok.ExpiresAt, ttl)
	}
}

func TestSingleProfileLogin(t *testing.T) {
	ctx := context.Background()
	f, c := newFakeBML(t, 1)

	a, err := c.Begin(ctx, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Channels) != 2 || a.Channels[0].Masked != "96****2238" {
		t.Fatalf("channels = %+v", a.Channels)
	}
	if err := a.SendOTP(ctx, "mobile"); err != nil {
		t.Fatal(err)
	}
	if len(f.sentVia) != 1 || f.sentVia[0] != "mobile" {
		t.Errorf("OTP sent via %v, want [mobile]", f.sentVia)
	}
	step, err := a.VerifyOTP(ctx, testOTP, "mobile")
	if err != nil {
		t.Fatal(err)
	}
	checkTokens(t, step.Tokens, "ACCESS", time.Hour)
	if step.Tokens.RefreshToken != "REFRESH" {
		t.Errorf("refresh token = %q", step.Tokens.RefreshToken)
	}
}

func TestWrongOTPCanBeRetried(t *testing.T) {
	ctx := context.Background()
	_, c := newFakeBML(t, 1)
	a, err := c.Begin(ctx, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.VerifyOTP(ctx, "000000", "authenticator")
	if !errors.Is(err, ErrOTPRejected) || !strings.Contains(err.Error(), "Invalid OTP") {
		t.Fatalf("err = %v, want ErrOTPRejected with BML's message", err)
	}
	step, err := a.VerifyOTP(ctx, testOTP, "authenticator")
	if err != nil {
		t.Fatal(err)
	}
	checkTokens(t, step.Tokens, "ACCESS", time.Hour)
}

func TestInvalidCredentials(t *testing.T) {
	_, c := newFakeBML(t, 1)
	_, err := c.Begin(context.Background(), "user", "wrong")
	if !errors.Is(err, ErrInvalidCredentials) || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("err = %v, want ErrInvalidCredentials with BML's message", err)
	}
}

func TestMultiProfilePersonal(t *testing.T) {
	ctx := context.Background()
	_, c := newFakeBML(t, 2)
	a, err := c.Begin(ctx, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	step, err := a.VerifyOTP(ctx, testOTP, "authenticator")
	if err != nil {
		t.Fatal(err)
	}
	if len(step.Profiles) != 2 || step.Profiles[1].Details.CustomerType != "Business" {
		t.Fatalf("profiles = %+v", step.Profiles)
	}
	step, err = a.SelectProfile(ctx, personalID)
	if err != nil {
		t.Fatal(err)
	}
	checkTokens(t, step.Tokens, "ACCESS", time.Hour)
}

func TestMultiProfileBusiness(t *testing.T) {
	ctx := context.Background()
	_, c := newFakeBML(t, 2)
	a, err := c.Begin(ctx, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyOTP(ctx, testOTP, "authenticator"); err != nil {
		t.Fatal(err)
	}
	step, err := a.SelectProfile(ctx, businessID)
	if err != nil {
		t.Fatal(err)
	}
	if len(step.BusinessChannels) != 2 {
		t.Fatalf("business channels = %+v", step.BusinessChannels)
	}
	if _, err := a.SendBusinessOTP(ctx, "Mobile"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyBusinessOTP(ctx, "111111", "Mobile"); !errors.Is(err, ErrOTPRejected) {
		t.Fatalf("err = %v, want ErrOTPRejected", err)
	}
	tok, err := a.VerifyBusinessOTP(ctx, testBusinessOTP, "Mobile")
	if err != nil {
		t.Fatal(err)
	}
	checkTokens(t, tok, "ACCESS", time.Hour)
}

func TestInertiaLocationIsFollowed(t *testing.T) {
	ctx := context.Background()
	_, c := newFakeBML(t, 2)
	a, err := c.Begin(ctx, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyOTP(ctx, testOTP, "authenticator"); err != nil {
		t.Fatal(err)
	}
	step, err := a.SelectProfile(ctx, inertiaID)
	if err != nil {
		t.Fatal(err)
	}
	checkTokens(t, step.Tokens, "ACCESS", time.Hour)
}

func TestRefresh(t *testing.T) {
	ctx := context.Background()
	_, c := newFakeBML(t, 1)
	tok, err := c.Refresh(ctx, "ACCESS", "REFRESH")
	if err != nil {
		t.Fatal(err)
	}
	checkTokens(t, tok, "ACCESS2", 2*time.Hour)

	if _, err := c.Refresh(ctx, "ACCESS", "stale"); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestExtractPropsUnescapesEntities(t *testing.T) {
	body := `<div class="x" id="app" data-page="{&quot;props&quot;:{&quot;channels&quot;:[{&quot;channel&quot;:&quot;mobile&quot;,&quot;description&quot;:&quot;A &amp; B&quot;,&quot;masked&quot;:&quot;&lt;x&gt;&quot;}]}}"></div>`
	props, err := extractProps([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if got := props.Channels[0]; got.Description != "A & B" || got.Masked != "<x>" {
		t.Fatalf("channel = %+v", got)
	}
	if _, err := extractProps([]byte("<html>blocked</html>")); !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("err = %v, want ErrUnexpectedResponse", err)
	}
}

func TestPKCEChallengeMatchesVerifier(t *testing.T) {
	p := newPKCE()
	sum := sha256.Sum256([]byte(p.verifier))
	if len(p.verifier) != 64 || len(p.state) != 32 || len(p.nonce) != 32 {
		t.Fatalf("unexpected lengths: %+v", p)
	}
	if base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge {
		t.Fatal("challenge is not S256(verifier)")
	}
}
