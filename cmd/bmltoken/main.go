// Command bmltoken logs in to Bank of Maldives internet banking on your own
// computer and prints an access token you can paste into other tools.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"charm.land/huh/v2"

	"github.com/chumputys/bmltokengenerator/internal/bml"
	"github.com/chumputys/bmltokengenerator/internal/device"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `bmltoken: generate a Bank of Maldives API token on your own computer.

Usage:
  bmltoken [login] [flags]    Log in and print an access token
  bmltoken refresh [flags]    Exchange a refresh token for a new access token
  bmltoken version            Print the version

Login flags:
  -u, --username string   BML username (prompted when omitted)
  -p, --profile string    Profile name or ID to pick without prompting
      --json              Print the result as JSON

Refresh flags:
      --json              Print the result as JSON

Your password is only sent to www.bankofmaldives.com.mv and is never stored.

Environment overrides (rarely needed):
  BML_CLIENT_ID, BML_APP_VERSION, BML_IOS_VERSION, BML_DEVICE_ID,
  BML_TOKEN_USER_AGENT
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := run(ctx, os.Args[1:])
	switch {
	case err == nil:
	case errors.Is(err, huh.ErrUserAborted), errors.Is(err, context.Canceled):
		fmt.Fprintln(os.Stderr, "Cancelled.")
		os.Exit(130)
	default:
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cmd := "login"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "login":
		return runLogin(ctx, args)
	case "refresh":
		return runRefresh(ctx, args)
	case "version":
		fmt.Println(version)
		return nil
	case "help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func newClient() (*bml.Client, error) {
	deviceID := os.Getenv("BML_DEVICE_ID")
	if deviceID == "" {
		var err error
		if deviceID, err = device.ID(); err != nil {
			return nil, err
		}
	}
	return bml.NewClient(bml.Config{
		BaseURL:    os.Getenv("BML_BASE_URL"),
		ClientID:   os.Getenv("BML_CLIENT_ID"),
		DeviceID:   deviceID,
		AppVersion: os.Getenv("BML_APP_VERSION"),
		IOSVersion: os.Getenv("BML_IOS_VERSION"),
		// Experimental: BML labels the token on its devices page from this.
		TokenUserAgent: os.Getenv("BML_TOKEN_USER_AGENT"),
	})
}
