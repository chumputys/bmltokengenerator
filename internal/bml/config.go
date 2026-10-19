// Package bml implements the Bank of Maldives internet banking OAuth login
// flow used by the BML mobile app: PKCE authorize, username/password login,
// personal 2FA, optional profile selection, optional business 2FA, and the
// authorization-code exchange for access and refresh tokens.
package bml

import (
	"strings"
)

const (
	DefaultBaseURL        = "https://www.bankofmaldives.com.mv"
	DefaultClientID       = "98C83590-513F-4716-B02B-EC68B7D9E7E7"
	DefaultCallbackScheme = "mv.com.bml.mib"
	DefaultAppVersion     = "2.1.44.348"
	DefaultIOSVersion     = "26.5.1"
	DefaultTokenUserAgent = "Mozilla/5.0 (Android 10; Mobile; rv:122.0) Gecko/122.0 Firefox/122.0"

	// scope requested by the mobile app.
	scope = "view-summary"
)

// Config holds the protocol values sent to BML. Only DeviceID has no
// default; it should be stable per installation.
type Config struct {
	BaseURL        string
	ClientID       string
	DeviceID       string
	CallbackScheme string
	AppVersion     string
	IOSVersion     string
	// TokenUserAgent is the User-Agent for the token exchange and refresh.
	// BML derives the label on its "devices" page from it.
	TokenUserAgent string
}

func (c Config) withDefaults() Config {
	if c.BaseURL == "" {
		c.BaseURL = DefaultBaseURL
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.ClientID == "" {
		c.ClientID = DefaultClientID
	}
	if c.CallbackScheme == "" {
		c.CallbackScheme = DefaultCallbackScheme
	}
	if c.AppVersion == "" {
		c.AppVersion = DefaultAppVersion
	}
	if c.IOSVersion == "" {
		c.IOSVersion = DefaultIOSVersion
	}
	if c.TokenUserAgent == "" {
		c.TokenUserAgent = DefaultTokenUserAgent
	}
	return c
}

// CallbackURI is the custom-scheme redirect the mobile app registers,
// e.g. mv.com.bml.mib://oauth/callback.
func (c Config) CallbackURI() string {
	return c.CallbackScheme + "://oauth/callback"
}

// buildNumber is the trailing segment of AppVersion (348 from 2.1.44.348).
// The app sends the full version in x-app-version but only the build
// number in its User-Agent.
func (c Config) buildNumber() string {
	parts := strings.Split(c.AppVersion, ".")
	if last := parts[len(parts)-1]; last != "" {
		return last
	}
	return c.AppVersion
}

func (c Config) appUserAgent() string {
	return "bml-mobile-banking/" + c.buildNumber() + " (iPhone; CPU iPhone OS " + c.IOSVersion + "; MG7K4)"
}
