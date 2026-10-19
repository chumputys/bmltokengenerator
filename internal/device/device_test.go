package device

import (
	"path/filepath"
	"regexp"
	"testing"
)

func TestIDIsCreatedOnceAndReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bmltoken", "device_id")
	first, err := idAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$`).MatchString(first) {
		t.Fatalf("id %q is not an uppercase v4 UUID", first)
	}
	second, err := idAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("id changed between runs: %q then %q", first, second)
	}
}
