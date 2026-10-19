package bml

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

var (
	// ErrInvalidCredentials means BML did not accept the username/password.
	ErrInvalidCredentials = errors.New("invalid username or password")
	// ErrOTPRejected means BML did not accept a one-time password. The
	// attempt is still usable; the code can be submitted again.
	ErrOTPRejected = errors.New("OTP rejected")
	// ErrInvalidRefreshToken means BML rejected a refresh token.
	ErrInvalidRefreshToken = errors.New("refresh token rejected")
	// ErrUnexpectedResponse means BML answered in a way this tool does not
	// understand, usually because the flow or bot protection changed.
	ErrUnexpectedResponse = errors.New("unexpected response from BML")
)

// OTPChannel is a delivery option for a one-time password.
type OTPChannel struct {
	Channel     string `json:"channel"`
	Description string `json:"description"`
	Masked      string `json:"masked"`
}

// Profile is one of the user's internet banking profiles.
type Profile struct {
	ID      string `json:"profile_id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Owner   string `json:"owner"`
	Details struct {
		Name           string `json:"name"`
		CustomerNumber string `json:"customer_number"`
		CustomerType   string `json:"customer_type"`
		ProfileType    string `json:"profile_type"`
	} `json:"profile"`
}

// Tokens is the result of a successful login or refresh.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Step is what the flow needs next after an OTP or profile selection.
// Exactly one field is set.
type Step struct {
	// Tokens is set when login is complete.
	Tokens *Tokens
	// Profiles is set when the user must choose a profile.
	Profiles []Profile
	// BusinessChannels is set when the chosen business profile needs its
	// own 2FA; call SendBusinessOTP then VerifyBusinessOTP.
	BusinessChannels []OTPChannel
}

// Attempt is one in-flight login. It holds the PKCE values and the session
// cookies, so every step of a login must use the same Attempt.
type Attempt struct {
	c    *Client
	hc   *http.Client
	pkce pkce

	// Channels are the personal 2FA delivery options offered after login.
	Channels []OTPChannel
}

// Begin starts the OAuth flow and submits the username and password. On
// success BML is waiting for the personal OTP.
func (c *Client) Begin(ctx context.Context, username, password string) (*Attempt, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	a := &Attempt{c: c, hc: c.newHTTPClient(jar), pkce: newPKCE()}

	res, err := c.send(ctx, a.hc, request{
		method: http.MethodGet,
		path:   "internetbanking/oauth/authorize",
		query: url.Values{
			"redirect_uri":          {c.cfg.CallbackURI()},
			"client_id":             {c.cfg.ClientID},
			"response_type":         {"code"},
			"state":                 {a.pkce.state},
			"nonce":                 {a.pkce.nonce},
			"code_challenge":        {a.pkce.challenge},
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
		return nil, err
	}
	if res.status != http.StatusFound {
		return nil, fmt.Errorf("%w: authorize returned HTTP %d%s", ErrUnexpectedResponse, res.status, blockedHint(res))
	}

	res, err = c.send(ctx, a.hc, request{
		method:       http.MethodPost,
		path:         "internetbanking/web/login",
		form:         url.Values{"username": {username}, "password": {password}, "code": {""}},
		persona:      personaWebForm,
		maxRedirects: 5,
	})
	if err != nil {
		return nil, err
	}
	props, err := extractProps(res.body)
	if err != nil {
		return nil, fmt.Errorf("login: %w%s", err, blockedHint(res))
	}
	if len(props.Channels) == 0 {
		if msg := props.message(); msg != "" {
			return nil, fmt.Errorf("%w: %s", ErrInvalidCredentials, msg)
		}
		return nil, ErrInvalidCredentials
	}
	a.Channels = props.Channels
	return a, nil
}

// SendOTP asks BML to deliver the personal OTP on channel (one of the
// Channel values from Channels). Not needed for the authenticator app.
func (a *Attempt) SendOTP(ctx context.Context, channel string) error {
	channels, err := a.toggleChannel(ctx, "internetbanking/web/login/2fa", channel)
	if err != nil {
		return err
	}
	a.Channels = channels
	return nil
}

// VerifyOTP submits the personal OTP received on channel.
func (a *Attempt) VerifyOTP(ctx context.Context, code, channel string) (*Step, error) {
	res, err := a.c.send(ctx, a.hc, request{
		method:       http.MethodPost,
		path:         "internetbanking/web/login/2fa",
		form:         url.Values{"code": {code}, "channel": {channel}},
		persona:      personaWebForm,
		maxRedirects: 2,
	})
	if err != nil {
		return nil, err
	}
	if res.callbackCode != "" {
		return a.complete(ctx, res.callbackCode)
	}
	props, err := extractProps(res.body)
	if err != nil {
		return nil, fmt.Errorf("verify OTP: %w", err)
	}
	if len(props.Profiles) == 0 {
		return nil, otpRejected(props)
	}
	return &Step{Profiles: props.Profiles}, nil
}

// SelectProfile picks the profile to issue the token for. A personal
// profile completes the login; a business profile needs its own 2FA.
func (a *Attempt) SelectProfile(ctx context.Context, profileID string) (*Step, error) {
	res, err := a.c.send(ctx, a.hc, request{
		method:       http.MethodGet,
		path:         "internetbanking/web/profile/" + url.PathEscape(profileID),
		persona:      personaWebForm,
		maxRedirects: 1,
	})
	if err != nil {
		return nil, err
	}
	// Inertia clients get 409 + X-Inertia-Location instead of a redirect.
	if res.callbackCode == "" && res.status == http.StatusConflict {
		if loc := res.header.Get("X-Inertia-Location"); loc != "" {
			res, err = a.followInertiaLocation(ctx, loc)
			if err != nil {
				return nil, err
			}
		}
	}
	if res.callbackCode != "" {
		return a.complete(ctx, res.callbackCode)
	}
	if res.status != http.StatusOK {
		return nil, fmt.Errorf("%w: profile selection returned HTTP %d", ErrUnexpectedResponse, res.status)
	}
	props, err := extractProps(res.body)
	if err != nil {
		return nil, fmt.Errorf("select profile: %w", err)
	}
	if len(props.Channels) == 0 {
		return nil, fmt.Errorf("%w: business profile offered no OTP channels", ErrUnexpectedResponse)
	}
	return &Step{BusinessChannels: props.Channels}, nil
}

func (a *Attempt) followInertiaLocation(ctx context.Context, loc string) (*response, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return nil, fmt.Errorf("%w: bad X-Inertia-Location %q", ErrUnexpectedResponse, loc)
	}
	return a.c.send(ctx, a.hc, request{
		method:       http.MethodGet,
		path:         u.Path,
		query:        u.Query(),
		persona:      personaWebForm,
		maxRedirects: 2,
	})
}

// SendBusinessOTP asks BML to deliver the business-profile OTP on channel
// (one of the Channel values from Step.BusinessChannels, e.g. "Mobile").
func (a *Attempt) SendBusinessOTP(ctx context.Context, channel string) ([]OTPChannel, error) {
	return a.toggleChannel(ctx, "internetbanking/web/profile/2fa/business", channel)
}

// VerifyBusinessOTP submits the business-profile OTP and completes login.
func (a *Attempt) VerifyBusinessOTP(ctx context.Context, code, channel string) (*Tokens, error) {
	res, err := a.c.send(ctx, a.hc, request{
		method:       http.MethodPost,
		path:         "internetbanking/web/profile/2fa/business",
		form:         url.Values{"code": {code}, "channel": {channel}},
		persona:      personaWebForm,
		maxRedirects: 1,
	})
	if err != nil {
		return nil, err
	}
	if res.callbackCode == "" {
		props, err := extractProps(res.body)
		if err != nil {
			return nil, fmt.Errorf("verify business OTP: %w", err)
		}
		return nil, otpRejected(props)
	}
	step, err := a.complete(ctx, res.callbackCode)
	if err != nil {
		return nil, err
	}
	return step.Tokens, nil
}

// toggleChannel submits an empty code with channel, which makes BML send
// the OTP there, and returns the refreshed channel list.
func (a *Attempt) toggleChannel(ctx context.Context, path, channel string) ([]OTPChannel, error) {
	res, err := a.c.send(ctx, a.hc, request{
		method:       http.MethodPost,
		path:         path,
		form:         url.Values{"code": {""}, "channel": {channel}},
		persona:      personaWebForm,
		maxRedirects: 5,
	})
	if err != nil {
		return nil, err
	}
	props, err := extractProps(res.body)
	if err != nil {
		return nil, fmt.Errorf("send OTP: %w", err)
	}
	if len(props.Channels) == 0 {
		if msg := props.message(); msg != "" {
			return nil, fmt.Errorf("%w: sending OTP via %s failed: %s", ErrUnexpectedResponse, channel, msg)
		}
		return nil, fmt.Errorf("%w: sending OTP via %s failed", ErrUnexpectedResponse, channel)
	}
	return props.Channels, nil
}

// complete exchanges the authorization code for tokens.
func (a *Attempt) complete(ctx context.Context, code string) (*Step, error) {
	c := a.c
	res, err := c.send(ctx, c.newHTTPClient(nil), request{
		method: http.MethodPost,
		path:   "internetbanking/oauth/token",
		form: url.Values{
			"redirect_uri":          {c.cfg.CallbackURI()},
			"client_id":             {c.cfg.ClientID},
			"grant_type":            {"authorization_code"},
			"code":                  {code},
			"code_challenge":        {a.pkce.challenge},
			"code_challenge_method": {"S256"},
			"code_verifier":         {a.pkce.verifier},
		},
		persona:      personaToken,
		maxRedirects: 5,
	})
	if err != nil {
		return nil, err
	}
	tokens, err := parseTokens(res)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	return &Step{Tokens: tokens}, nil
}

// Refresh exchanges a refresh token for a new access token. It needs no
// login attempt.
func (c *Client) Refresh(ctx context.Context, accessToken, refreshToken string) (*Tokens, error) {
	res, err := c.send(ctx, c.newHTTPClient(nil), request{
		method: http.MethodPost,
		path:   "internetbanking/oauth/token",
		form: url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {c.cfg.ClientID},
			"scope":         {scope},
		},
		persona:      personaRefresh,
		maxRedirects: 5,
		bearer:       accessToken,
	})
	if err != nil {
		return nil, err
	}
	if res.status == http.StatusUnauthorized {
		return nil, ErrInvalidRefreshToken
	}
	tokens, err := parseTokens(res)
	if err != nil {
		return nil, fmt.Errorf("refresh: %w", err)
	}
	return tokens, nil
}

func parseTokens(res *response) (*Tokens, error) {
	var raw struct {
		AccessToken  string      `json:"access_token"`
		RefreshToken string      `json:"refresh_token"`
		ExpiresIn    json.Number `json:"expires_in"`
	}
	if err := json.Unmarshal(res.body, &raw); err != nil || raw.AccessToken == "" {
		return nil, fmt.Errorf("%w: no access token in HTTP %d response", ErrUnexpectedResponse, res.status)
	}
	expiresIn, err := raw.ExpiresIn.Int64()
	if err != nil {
		return nil, fmt.Errorf("%w: invalid expires_in %q", ErrUnexpectedResponse, raw.ExpiresIn)
	}
	return &Tokens{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		ExpiresIn:    int(expiresIn),
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second).Truncate(time.Second),
	}, nil
}

func otpRejected(props pageProps) error {
	if msg := props.message(); msg != "" {
		return fmt.Errorf("%w: %s", ErrOTPRejected, msg)
	}
	return ErrOTPRejected
}

// blockedHint adds a note when a response looks like a Cloudflare block
// rather than a BML page.
func blockedHint(res *response) string {
	if res.status == http.StatusForbidden || res.status == http.StatusServiceUnavailable ||
		strings.Contains(string(res.body), "cf-chl") || strings.Contains(string(res.body), "Just a moment") {
		return " (the request looks blocked by Cloudflare bot protection)"
	}
	return ""
}
