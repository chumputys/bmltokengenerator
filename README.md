<img src="assets/icon.svg" width="64" height="64" alt="">

# bmltoken

Generate a Bank of Maldives (BML) internet banking token on your own computer.

Some tools ask you for a BML access token instead of your username and password. `bmltoken` lets you create that token yourself, so your credentials never pass through anyone else's server. It logs in the same way the BML mobile app does, walks you through 2FA and profile selection, and prints the token and its expiry.

> **Not an official BML product.** This is a community tool that follows the mobile app's login flow. BML can change that flow at any time.

## What it does with your credentials

- Your username, password and OTPs are sent **only** to `www.bankofmaldives.com.mv`.
- Nothing is saved to disk except a random device ID (see [Device ID](#device-id)).
- No telemetry and no other network calls. The code is small; read it before you trust it: [`internal/bml`](internal/bml).

## Install

### Download a release

Grab the archive for your system from [Releases](https://github.com/chumputys/bmltokengenerator/releases):

| System | File |
|---|---|
| macOS (Apple silicon) | `bmltoken_<version>_darwin_arm64.tar.gz` |
| macOS (Intel) | `bmltoken_<version>_darwin_amd64.tar.gz` |
| Windows | `bmltoken_<version>_windows_amd64.zip` |
| Linux | `bmltoken_<version>_linux_amd64.tar.gz` |

Every release is built by GitHub Actions from the tagged source. You can check that a download came from this repository with the [GitHub CLI](https://cli.github.com):

```sh
gh attestation verify bmltoken_<version>_darwin_arm64.tar.gz --repo chumputys/bmltokengenerator
```

**macOS:** the binary is not notarized yet. If macOS refuses to open it, remove the quarantine flag:

```sh
xattr -d com.apple.quarantine ./bmltoken
```

**Windows:** SmartScreen may warn about an unrecognized app. Choose **More info → Run anyway**.

### Build from source

Requires Go 1.25+.

```sh
go install github.com/chumputys/bmltokengenerator/cmd/bmltoken@latest
```

## Usage

```sh
bmltoken
```

You'll be asked for:

1. Your BML username and password.
2. Where to receive the OTP (authenticator app, SMS, WhatsApp, …) and the code itself.
3. Which profile the token is for, if you have more than one.
4. A second OTP, if you chose a business profile.

The result:

```
Profile:  Personal

Access token:
eyJ0eXAiOiJKV1QiLCJhbGciOi...

Expires at: 2026-10-20T00:21:00+05:00 (in 1h0m0s)

Refresh token (keep this private; it can mint new access tokens with `bmltoken refresh`):
def50200...
```

Paste the access token and the expiry into the tool that asked for them.

### Options

```
bmltoken [login] [flags]    Log in and print an access token
bmltoken refresh [flags]    Exchange a refresh token for a new access token
bmltoken version            Print the version

  -u, --username string   BML username (prompted when omitted)
  -p, --profile string    Profile name or ID to pick without prompting
      --json              Print the result as JSON
```

`--json` writes only the result to stdout (prompts go to stderr), so you can save it:

```sh
bmltoken --json > token.json
```

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi...",
  "refresh_token": "def50200...",
  "expires_in": 3600,
  "expires_at": "2026-10-20T00:21:00+05:00",
  "profile": { "id": "A54898AF-...", "name": "Personal" }
}
```

### Refreshing

```sh
bmltoken refresh            # prompts for the refresh token
bmltoken refresh < token.json
```

Tokens are never taken as command-line arguments, so they don't end up in your shell history.

## Things to know

**Treat the token like your password.** The login requests the `view-summary` scope, but there is no evidence BML restricts what a token can do based on scope. Assume anyone holding the token can do anything you can in internet banking until it expires. Only give it to tools you trust, and prefer giving out the short-lived access token rather than the refresh token.

**Revoking a token.** Every login shows up in BML internet banking under **2FA → Devices** as *Android Mobile App, Android 10, android*, with the date and time it was created. Log that entry out to invalidate the token. BML builds that label from parsed User-Agent fields, so it can't be set to a custom name; use the timestamp to tell entries apart.

### Device ID

On first run `bmltoken` generates a random device ID and stores it in your user config directory (`~/Library/Application Support/bmltoken/device_id` on macOS, `%AppData%\bmltoken\device_id` on Windows, `~/.config/bmltoken/device_id` on Linux). It is sent to BML on every login so you appear as the same device each time. Delete the file to get a new one.

### Environment overrides

Rarely needed; they exist in case BML changes what it expects.

| Variable | Default |
|---|---|
| `BML_CLIENT_ID` | the mobile app's OAuth client ID |
| `BML_APP_VERSION` | `2.1.44.348` |
| `BML_IOS_VERSION` | `26.5.1` |
| `BML_DEVICE_ID` | the stored device ID |
| `BML_TOKEN_USER_AGENT` | the User-Agent used for the token exchange and refresh |

## Development

```sh
go test ./...                                              # offline tests against a fake BML server
go test -tags live -run TestLiveAuthorize -v ./internal/bml  # checks the real site accepts the client (no credentials sent)
go build -o bin/bmltoken ./cmd/bmltoken
```

Releases are cut by pushing a tag (`git tag v0.1.0 && git push origin v0.1.0`); GoReleaser builds macOS, Windows and Linux binaries and GitHub attaches build provenance.

## License

MIT. See [LICENSE](LICENSE).
