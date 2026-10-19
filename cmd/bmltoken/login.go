package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"charm.land/huh/v2"

	"github.com/chumputys/bmltokengenerator/internal/bml"
)

// maxOTPTries is how many times a rejected OTP may be re-entered.
const maxOTPTries = 3

func runLogin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	var username, profile string
	var asJSON bool
	fs.StringVar(&username, "username", "", "")
	fs.StringVar(&username, "u", "", "")
	fs.StringVar(&profile, "profile", "", "")
	fs.StringVar(&profile, "p", "", "")
	fs.BoolVar(&asJSON, "json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireTerminal(); err != nil {
		return err
	}

	client, err := newClient()
	if err != nil {
		return err
	}

	if username == "" {
		if err := huh.NewInput().
			Title("BML username").
			Validate(required("username")).
			Value(&username).
			Run(); err != nil {
			return err
		}
	}
	var password string
	if err := huh.NewInput().
		Title("Password").
		EchoMode(huh.EchoModePassword).
		Validate(required("password")).
		Value(&password).
		Run(); err != nil {
		return err
	}

	var attempt *bml.Attempt
	err = busy(ctx, "Signing in…", func(ctx context.Context) error {
		a, err := client.Begin(ctx, strings.TrimSpace(username), password)
		attempt = a
		return err
	})
	password = ""
	if err != nil {
		return err
	}

	channel, err := pickChannel("Where should BML send your OTP?", attempt.Channels)
	if err != nil {
		return err
	}
	if !strings.EqualFold(channel.Channel, "authenticator") {
		if err := busy(ctx, "Sending OTP via "+channel.Description+"…", func(ctx context.Context) error {
			return attempt.SendOTP(ctx, channel.Channel)
		}); err != nil {
			return err
		}
	}

	var step *bml.Step
	err = withOTP(ctx, otpTitle(channel), func(ctx context.Context, code string) error {
		s, err := attempt.VerifyOTP(ctx, code, channel.Channel)
		step = s
		return err
	})
	if err != nil {
		return err
	}

	var chosen *bml.Profile
	if len(step.Profiles) > 0 {
		if chosen, err = pickProfile(step.Profiles, profile); err != nil {
			return err
		}
		if err := busy(ctx, "Selecting "+chosen.Name+"…", func(ctx context.Context) error {
			s, err := attempt.SelectProfile(ctx, chosen.ID)
			step = s
			return err
		}); err != nil {
			return err
		}
	}

	if len(step.BusinessChannels) > 0 {
		tokens, err := businessOTP(ctx, attempt, step.BusinessChannels)
		if err != nil {
			return err
		}
		step = &bml.Step{Tokens: tokens}
	}

	return printTokens(step.Tokens, chosen, asJSON)
}

func businessOTP(ctx context.Context, attempt *bml.Attempt, channels []bml.OTPChannel) (*bml.Tokens, error) {
	channel, err := pickChannel("This business profile needs its own OTP. Where should BML send it?", channels)
	if err != nil {
		return nil, err
	}
	if err := busy(ctx, "Requesting business OTP via "+channel.Description+"…", func(ctx context.Context) error {
		_, err := attempt.SendBusinessOTP(ctx, channel.Channel)
		return err
	}); err != nil {
		return nil, err
	}

	var tokens *bml.Tokens
	err = withOTP(ctx, "Business "+otpTitle(channel), func(ctx context.Context, code string) error {
		t, err := attempt.VerifyBusinessOTP(ctx, code, channel.Channel)
		tokens = t
		return err
	})
	return tokens, err
}

// withOTP prompts for a code and runs verify, re-prompting when BML
// rejects the code.
func withOTP(ctx context.Context, title string, verify func(context.Context, string) error) error {
	for try := 1; ; try++ {
		var code string
		if err := huh.NewInput().
			Title(title).
			Validate(required("OTP")).
			Value(&code).
			Run(); err != nil {
			return err
		}
		err := busy(ctx, "Verifying…", func(ctx context.Context) error {
			return verify(ctx, strings.TrimSpace(code))
		})
		if err == nil || !errors.Is(err, bml.ErrOTPRejected) || try == maxOTPTries {
			return err
		}
		fmt.Fprintf(os.Stderr, "%v. Try again (%d of %d).\n", err, try+1, maxOTPTries)
	}
}

func otpTitle(ch bml.OTPChannel) string {
	if strings.EqualFold(ch.Channel, "authenticator") {
		return "OTP from your authenticator app"
	}
	return "OTP sent to " + channelLabel(ch)
}

func channelLabel(ch bml.OTPChannel) string {
	label := ch.Description
	if label == "" {
		label = ch.Channel
	}
	if ch.Masked != "" {
		label += " (" + ch.Masked + ")"
	}
	return label
}

// pickChannel asks which OTP channel to use. The authenticator app is
// offered first because it needs no round trip to deliver a code.
func pickChannel(title string, channels []bml.OTPChannel) (bml.OTPChannel, error) {
	if len(channels) == 1 {
		return channels[0], nil
	}
	opts := make([]huh.Option[int], 0, len(channels))
	for i, ch := range channels {
		opt := huh.NewOption(channelLabel(ch), i)
		if strings.EqualFold(ch.Channel, "authenticator") {
			opts = append([]huh.Option[int]{opt}, opts...)
		} else {
			opts = append(opts, opt)
		}
	}
	var idx int
	if err := huh.NewSelect[int]().Title(title).Options(opts...).Value(&idx).Run(); err != nil {
		return bml.OTPChannel{}, err
	}
	return channels[idx], nil
}

// pickProfile selects the profile matching want (by ID or name), or asks.
func pickProfile(profiles []bml.Profile, want string) (*bml.Profile, error) {
	if want != "" {
		for i := range profiles {
			if strings.EqualFold(profiles[i].ID, want) || strings.EqualFold(profiles[i].Name, want) {
				return &profiles[i], nil
			}
		}
		return nil, fmt.Errorf("no profile matches %q; available: %s", want, profileNames(profiles))
	}
	if len(profiles) == 1 {
		return &profiles[0], nil
	}
	opts := make([]huh.Option[int], len(profiles))
	for i, p := range profiles {
		opts[i] = huh.NewOption(profileLabel(p), i)
	}
	var idx int
	if err := huh.NewSelect[int]().Title("Which profile is the token for?").Options(opts...).Value(&idx).Run(); err != nil {
		return nil, err
	}
	return &profiles[idx], nil
}

func profileLabel(p bml.Profile) string {
	var tags []string
	if p.Details.CustomerType != "" {
		tags = append(tags, p.Details.CustomerType)
	}
	if p.Details.ProfileType == "default" {
		tags = append(tags, "default")
	}
	if len(tags) == 0 {
		return p.Name
	}
	return p.Name + " (" + strings.Join(tags, ", ") + ")"
}

func profileNames(profiles []bml.Profile) string {
	names := make([]string, len(profiles))
	for i, p := range profiles {
		names[i] = fmt.Sprintf("%q", p.Name)
	}
	return strings.Join(names, ", ")
}

func required(what string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", what)
		}
		return nil
	}
}
