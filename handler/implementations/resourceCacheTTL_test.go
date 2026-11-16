package implementations

import (
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

func TestResourceCacheTTL(t *testing.T) {
	previous := resourceCacheOverride.Load()
	defer resourceCacheOverride.Store(previous)
	if err := ConfigureResourceCacheTTL(200*time.Millisecond, false); err != nil {
		t.Fatal(err)
	}
	if got := resourceCacheTTL(nil, procUptimeSnapshotTTL); got != 100*time.Millisecond {
		t.Fatalf("default uptime TTL = %s", got)
	}
	if got := resourceCacheTTL(nil, resourceSnapshotTTL); got != 200*time.Millisecond {
		t.Fatalf("default resource TTL = %s", got)
	}
	if err := ConfigureResourceCacheTTL(500*time.Millisecond, true); err != nil {
		t.Fatal(err)
	}
	if got := resourceCacheTTL(nil, procUptimeSnapshotTTL); got != 500*time.Millisecond {
		t.Fatalf("explicit uptime TTL = %s", got)
	}
	for _, tc := range []struct{ override, want time.Duration }{
		{0, 500 * time.Millisecond},
		{25 * time.Millisecond, 25 * time.Millisecond},
		{time.Second, 500 * time.Millisecond},
	} {
		req := &domain.HandlerRequest{ResourceCacheTTL: tc.override}
		if got := resourceCacheTTL(req, resourceSnapshotTTL); got != tc.want {
			t.Fatalf("container TTL %s: got %s want %s", tc.override, got, tc.want)
		}
	}
	for _, invalid := range []time.Duration{0, -time.Second} {
		if err := ConfigureResourceCacheTTL(invalid, true); err == nil {
			t.Fatal("accepted nonpositive global TTL")
		}
	}
}

func TestShortTTLDoesNotEvictOtherContainer(t *testing.T) {
	var cache byteSnapshots
	now := time.Now()
	read := func() ([]byte, error) { return []byte("snapshot"), nil }
	if _, err := cache.get("long", "long", nil, false, now, time.Second, read); err != nil {
		t.Fatal(err)
	}
	// Force a prune while the long-lived entry is still valid.
	cache.nextPrune = now
	if _, err := cache.get("short", "short", nil, false, now.Add(100*time.Millisecond), 25*time.Millisecond, read); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.cached("long", false, now.Add(100*time.Millisecond), time.Second); !ok {
		t.Fatal("short TTL evicted another container's valid snapshot")
	}
}
