package bml

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
)

// maxBodySize caps how much of a response body is read.
const maxBodySize = 8 << 20

// persona decides which client the outbound headers impersonate. BML's
// Cloudflare-fronted endpoints only accept requests whose headers look like
// a genuine client, and different phases of the flow need different ones.
type persona int

const (
	// personaOAuth is the iOS app making the OAuth authorize call.
	personaOAuth persona = iota
	// personaWebForm is the in-app webview carrying session cookies.
	personaWebForm
	// personaToken is a mobile browser exchanging the code for tokens.
	personaToken
	// personaRefresh is a JSON client refreshing an access token.
	personaRefresh
)

func (c *Client) headers(p persona) http.Header {
	h := http.Header{}
	switch p {
	case personaOAuth, personaWebForm:
		h.Set("x-app-version", c.cfg.AppVersion)
		h.Set("User-Agent", c.cfg.appUserAgent())
		h.Set("Accept-Language", "en-US")
		h.Set("Accept-Encoding", "gzip, deflate, br")
		h.Set("Upgrade-Insecure-Requests", "1")
		h.Set("Sec-Fetch-Dest", "document")
		h.Set("Sec-Fetch-Mode", "navigate")
		h.Set("Sec-Fetch-Site", "same-origin")
		h.Set("Sec-Fetch-User", "?1")
		h.Set("Te", "trailers")
		if p == personaOAuth {
			h.Set("Device-ID", c.cfg.DeviceID)
		}
	case personaToken:
		h.Set("User-Agent", c.cfg.TokenUserAgent)
		h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		h.Set("Accept-Language", "en-US")
		h.Set("Accept-Encoding", "gzip, deflate, br")
		h.Set("Upgrade-Insecure-Requests", "1")
		h.Set("Referer", c.cfg.BaseURL+"/internetbanking/web/login/2fa")
		h.Set("Sec-Fetch-Dest", "document")
		h.Set("Sec-Fetch-Mode", "navigate")
		h.Set("Sec-Fetch-Site", "same-origin")
		h.Set("Sec-Fetch-User", "?1")
		h.Set("Te", "trailers")
	case personaRefresh:
		h.Set("User-Agent", c.cfg.TokenUserAgent)
		h.Set("Accept", "application/json")
		h.Set("Accept-Encoding", "gzip, deflate, br")
	}
	return h
}

// Client talks to BML. It is safe to reuse across attempts; each login
// attempt gets its own cookie jar.
type Client struct {
	cfg       Config
	transport http.RoundTripper
}

// Option customises a Client.
type Option func(*Client)

// WithTransport replaces the HTTP transport (used by tests).
func WithTransport(rt http.RoundTripper) Option {
	return func(c *Client) { c.transport = rt }
}

// NewClient returns a Client for cfg. cfg.DeviceID is required.
func NewClient(cfg Config, opts ...Option) (*Client, error) {
	cfg = cfg.withDefaults()
	if cfg.DeviceID == "" {
		return nil, errors.New("bml: device ID is required")
	}
	c := &Client{cfg: cfg, transport: http.DefaultTransport}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// noRedirects is how many redirects to follow: none, return the 3xx as is.
const noRedirects = -1

type request struct {
	method       string
	path         string
	query        url.Values
	form         url.Values
	persona      persona
	maxRedirects int
	bearer       string
}

type response struct {
	status int
	header http.Header
	body   []byte
	// callbackCode is set when the redirect chain reached the app's custom
	// URI scheme; the chain stops there.
	callbackCode string
}

// send performs req, following redirects itself so every intermediate
// response can be checked for the custom-scheme callback, which net/http
// cannot follow.
func (c *Client) send(ctx context.Context, hc *http.Client, req request) (*response, error) {
	target, err := url.Parse(c.cfg.BaseURL + "/" + strings.TrimLeft(req.path, "/"))
	if err != nil {
		return nil, err
	}
	if len(req.query) > 0 {
		target.RawQuery = req.query.Encode()
	}

	method := req.method
	var body []byte
	if req.form != nil {
		body = []byte(req.form.Encode())
	}

	for redirects := 0; ; redirects++ {
		hreq, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		hreq.Header = c.headers(req.persona)
		if body != nil {
			hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			hreq.Body = http.NoBody
		}
		if req.bearer != "" {
			hreq.Header.Set("Authorization", "Bearer "+req.bearer)
		}

		hres, err := hc.Do(hreq)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", method, target.Path, err)
		}
		data, err := readBody(hres)
		hres.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%s %s: reading response: %w", method, target.Path, err)
		}
		res := &response{status: hres.StatusCode, header: hres.Header, body: data}

		location := hres.Header.Get("Location")
		if strings.HasPrefix(location, c.cfg.CallbackScheme+"://") {
			res.callbackCode = codeFromCallback(location)
			return res, nil
		}
		if !isRedirect(hres.StatusCode) || location == "" || req.maxRedirects == noRedirects {
			return res, nil
		}
		if redirects >= req.maxRedirects {
			return nil, fmt.Errorf("%w: too many redirects from %s", ErrUnexpectedResponse, req.path)
		}

		next, err := target.Parse(location)
		if err != nil {
			return nil, fmt.Errorf("%w: bad redirect location %q", ErrUnexpectedResponse, location)
		}
		target = next
		// Like browsers, 301/302/303 turn
		// into a GET without a body; 307/308 replay the request.
		if hres.StatusCode != http.StatusTemporaryRedirect && hres.StatusCode != http.StatusPermanentRedirect {
			method = http.MethodGet
			body = nil
		}
	}
}

// newHTTPClient returns an http.Client that never follows redirects on its
// own (send does that) and stores cookies in jar when one is given.
func (c *Client) newHTTPClient(jar http.CookieJar) *http.Client {
	return &http.Client{
		Transport: c.transport,
		Jar:       jar,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

func codeFromCallback(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Query().Get("code")
}

// readBody reads and decodes the body. Because we set Accept-Encoding
// ourselves, net/http leaves decompression to us.
func readBody(res *http.Response) ([]byte, error) {
	var r io.Reader = io.LimitReader(res.Body, maxBodySize)
	switch strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	case "br":
		r = brotli.NewReader(r)
	case "deflate":
		raw, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		// "deflate" is meant to be zlib-wrapped, but some servers send raw
		// deflate.
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			defer zr.Close()
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(raw))
		}
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", res.Header.Get("Content-Encoding"))
	}
	return io.ReadAll(io.LimitReader(r, maxBodySize))
}
