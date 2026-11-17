package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestRecoveryRetriesPolicyRefreshAfterMountReplacement(t *testing.T) {
	r := &recoveryRunner{}
	failed := errors.New("mountinfo temporarily unavailable")
	if err := r.refreshMountPolicy("container", []string{"/proc/meminfo"}, func(string, []string) error {
		return failed
	}); !errors.Is(err, failed) {
		t.Fatalf("first refresh error = %v, want %v", err, failed)
	}

	var refreshed []string
	if err := r.refreshMountPolicy("container", nil, func(_ string, paths []string) error {
		refreshed = append([]string(nil), paths...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(refreshed, []string{"/proc/meminfo"}) {
		t.Fatalf("retried paths = %v", refreshed)
	}
	if len(r.pendingMounts) != 0 {
		t.Fatalf("completed refresh still pending: %v", r.pendingMounts)
	}
}
