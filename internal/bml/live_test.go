//go:build live

package bml

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"golang.org/x/net/publicsuffix"
)

// TestLiveAuthorize checks that the real BML site (and Cloudflare in front
// of it) accepts this client up to the login page. It sends no credentials.
//
//	go test -tags live -run TestLiveAuthorize -v ./internal/bml
func TestLiveAuthorize(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(Config{DeviceID: "00000000-0000-4000-8000-000000000000"})
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	hc := c.newHTTPClient(jar)
	p := newPKCE()

	res, err := c.send(ctx, hc, request{
		method: http.MethodGet,
		path:   "internetbanking/oauth/authorize",
		query: url.Values{
			"redirect_uri":          {c.cfg.CallbackURI()},
			"client_id":             {c.cfg.ClientID},
			"response_type":         {"code"},
			"state":                 {p.state},
			"nonce":                 {p.nonce},
			"code_challenge":        {p.challenge},
			"code_challenge_method": {"S256"},
			"scope":                 {scope},
			"Device-ID":             {c.cfg.DeviceID},
			"User-Agent":            {c.cfg.appUserAgent()},
			"x-app-version":         {c.cfg.AppVersion},
		},
		persona:      personaOAuth,
		maxRedirects: noRedirects,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("authorize: HTTP %d, Location %q", res.status, res.header.Get("Location"))
	if res.status != http.StatusFound {
		t.Fatalf("authorize returned HTTP %d%s; body starts: %.300s", res.status, blockedHint(res), res.body)
	}

	res, err = c.send(ctx, hc, request{
		method:       http.MethodGet,
		path:         "internetbanking/web/login",
		persona:      personaWebForm,
		maxRedirects: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extractProps(res.body); err != nil {
		t.Fatalf("login page: HTTP %d: %v%s", res.status, err, blockedHint(res))
	}
	t.Logf("login page: HTTP %d with Inertia props", res.status)
}
