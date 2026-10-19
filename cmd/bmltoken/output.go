package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"charm.land/huh/v2/spinner"
	"golang.org/x/term"

	"github.com/chumputys/bmltokengenerator/internal/bml"
)

func requireTerminal() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("login is interactive; run it in a terminal")
	}
	return nil
}

// busy shows a spinner on stderr while fn talks to BML.
func busy(ctx context.Context, title string, fn func(context.Context) error) error {
	return spinner.New().Title(title).Context(ctx).ActionWithErr(fn).Run()
}

type profileOutput struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type tokenOutput struct {
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	ExpiresIn    int            `json:"expires_in"`
	ExpiresAt    string         `json:"expires_at"`
	Profile      *profileOutput `json:"profile,omitempty"`
}

// printTokens writes the result to stdout; prompts and spinners go to
// stderr, so `bmltoken --json > token.json` captures only the tokens.
func printTokens(t *bml.Tokens, p *bml.Profile, asJSON bool) error {
	if t == nil {
		return fmt.Errorf("%w: login finished without tokens", bml.ErrUnexpectedResponse)
	}
	expiresAt := t.ExpiresAt.Format(time.RFC3339)

	if asJSON {
		out := tokenOutput{
			AccessToken:  t.AccessToken,
			RefreshToken: t.RefreshToken,
			ExpiresIn:    t.ExpiresIn,
			ExpiresAt:    expiresAt,
		}
		if p != nil {
			out.Profile = &profileOutput{ID: p.ID, Name: p.Name}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Println()
	if p != nil {
		fmt.Printf("Profile:  %s\n\n", p.Name)
	}
	fmt.Println("Access token:")
	fmt.Println(t.AccessToken)
	fmt.Println()
	fmt.Printf("Expires at: %s (in %s)\n", expiresAt, time.Until(t.ExpiresAt).Round(time.Minute))
	if t.RefreshToken != "" {
		fmt.Println()
		fmt.Println("Refresh token (keep this private; it can mint new access tokens with `bmltoken refresh`):")
		fmt.Println(t.RefreshToken)
	}
	return nil
}
