package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"charm.land/huh/v2"
	"golang.org/x/term"

	"github.com/chumputys/bmltokengenerator/internal/bml"
)

// runRefresh exchanges a refresh token for new tokens. Tokens are read as
// JSON (the output of `bmltoken --json`) from stdin when it is piped, and
// prompted for otherwise, so they never end up in shell history.
func runRefresh(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client, err := newClient()
	if err != nil {
		return err
	}

	var in struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if err := huh.NewInput().
			Title("Refresh token").
			EchoMode(huh.EchoModePassword).
			Validate(required("refresh token")).
			Value(&in.RefreshToken).
			Run(); err != nil {
			return err
		}
		if err := huh.NewInput().
			Title("Current access token (optional)").
			EchoMode(huh.EchoModePassword).
			Value(&in.AccessToken).
			Run(); err != nil {
			return err
		}
	} else {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &in); err != nil {
			return fmt.Errorf("reading tokens from stdin: expected JSON with refresh_token: %w", err)
		}
		if in.RefreshToken == "" {
			return errors.New("reading tokens from stdin: refresh_token is missing")
		}
	}

	var tokens *bml.Tokens
	err = busy(ctx, "Refreshing…", func(ctx context.Context) error {
		t, err := client.Refresh(ctx, strings.TrimSpace(in.AccessToken), strings.TrimSpace(in.RefreshToken))
		tokens = t
		return err
	})
	if err != nil {
		return err
	}
	return printTokens(tokens, nil, asJSON)
}
