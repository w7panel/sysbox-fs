package implementations

import (
	"testing"
	"time"
)

func TestResourceCacheTTL(t *testing.T) {
	previous := resourceCacheOverride.Load()
	defer resourceCacheOverride.Store(previous)
	if err := ConfigureResourceCacheTTL(200*time.Millisecond, false); err != nil {
		t.Fatal(err)
	}
	if got := resourceCacheTTL(procUptimeSnapshotTTL); got != 100*time.Millisecond {
		t.Fatalf("default uptime TTL = %s", got)
	}
	if got := resourceCacheTTL(resourceSnapshotTTL); got != 200*time.Millisecond {
		t.Fatalf("default resource TTL = %s", got)
	}
	if err := ConfigureResourceCacheTTL(500*time.Millisecond, true); err != nil {
		t.Fatal(err)
	}
	if got := resourceCacheTTL(procUptimeSnapshotTTL); got != 500*time.Millisecond {
		t.Fatalf("explicit uptime TTL = %s", got)
	}
	if got := resourceCacheTTL(resourceSnapshotTTL); got != 500*time.Millisecond {
		t.Fatalf("explicit resource TTL = %s", got)
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
