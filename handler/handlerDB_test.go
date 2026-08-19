package handler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadHostUuid(t *testing.T) {
	dir := t.TempDir()

	t.Run("readable", func(t *testing.T) {
		path := filepath.Join(dir, "product_uuid")
		if err := os.WriteFile(path, []byte("12345678-1234-1234-1234-123456789abc\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readHostUuid(path)
		if err != nil {
			t.Fatal(err)
		}
		if want := "12345678-1234-1234-1234-123456789abc\n"; got != want {
			t.Fatalf("readHostUuid() = %q, want %q", got, want)
		}
	})

	t.Run("missing uses stable fallback", func(t *testing.T) {
		got, err := readHostUuid(filepath.Join(dir, "missing"))
		if err != nil {
			t.Fatal(err)
		}
		if got != fallbackHostUuid {
			t.Fatalf("readHostUuid() = %q, want %q", got, fallbackHostUuid)
		}
	})
}
