// Package device keeps a stable per-installation device ID, so BML sees the
// same "device" on every login instead of registering a new one each time.
package device

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ID returns the device ID stored under the user's config directory,
// creating one on first use.
func ID() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating config directory: %w", err)
	}
	return idAt(filepath.Join(dir, "bmltoken", "device_id"))
}

func idAt(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("reading device ID: %w", err)
	}

	id := newUUID()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("saving device ID: %w", err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("saving device ID: %w", err)
	}
	return id, nil
}

// newUUID returns an uppercase random (v4) UUID, the format iOS uses for
// identifierForVendor.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}
