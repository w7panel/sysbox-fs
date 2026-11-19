package fuse

import "testing"

func TestUnmountFuseAlreadyDetached(t *testing.T) {
	if err := unmountFuse(t.TempDir()); err != nil {
		t.Fatalf("already detached FUSE mount: %v", err)
	}
}
