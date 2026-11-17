package implementations

import (
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

func TestResourceReleaseClearsOnlyClosedLifetime(t *testing.T) {
	owner := &domain.ResourceOwner{ID: 901}
	other := &domain.ResourceOwner{ID: 902}
	req := &domain.HandlerRequest{ResourceOwner: owner}
	otherReq := &domain.HandlerRequest{ResourceOwner: other}
	key, otherKey := resourceOwnerKey(req), resourceOwnerKey(otherReq)
	now := time.Now()
	h := newReadOnlyResource("Test", "/proc/test", nil)
	for _, cache := range []*byteSnapshots{&h.snapshots, &procUptimeSnapshots} {
		for _, item := range []struct {
			key   string
			token *domain.ResourceOwner
		}{{key, owner}, {otherKey, other}} {
			if _, err := cache.get(item.key, item.key, item.token, false, now, time.Second, func() ([]byte, error) { return []byte("snapshot"), nil }); err != nil {
				t.Fatal(err)
			}
		}
	}
	loadavgSampler.Lock()
	node := &loadavgNode{owner: key}
	otherNode := &loadavgNode{owner: otherKey}
	loadavgSampler.nodes[key], loadavgSampler.nodes[otherKey] = node, otherNode
	loadavgSampler.Unlock()
	procStatStateForKey(req, key, now)
	procStatStateForKey(otherReq, otherKey, now)
	t.Cleanup(func() { ReleaseResourceOwner(other); h.ReleaseResourceSnapshots(otherKey) })
	ReleaseResourceOwner(owner)
	h.ReleaseResourceSnapshots(key)
	if !owner.Closed() || other.Closed() {
		t.Fatal("incorrect lifetime closure")
	}
	for _, cache := range []*byteSnapshots{&h.snapshots, &procUptimeSnapshots} {
		cache.mu.RLock()
		_, closedPresent := cache.entries[key]
		_, otherPresent := cache.entries[otherKey]
		cache.mu.RUnlock()
		if closedPresent || !otherPresent {
			t.Fatal("incorrect snapshot cleanup")
		}
	}
	loadavgSampler.Lock()
	_, closedPresent := loadavgSampler.nodes[key]
	_, otherPresent := loadavgSampler.nodes[otherKey]
	loadavgSampler.Unlock()
	if closedPresent || !otherPresent || !node.closed {
		t.Fatal("incorrect sampler cleanup")
	}
	// A request that reached proc/stat before shutdown must not reinsert state.
	procStatStateForKey(req, key, now)
	procStatStatesMu.Lock()
	_, closedPresent = procStatStates[key]
	_, otherPresent = procStatStates[otherKey]
	procStatStatesMu.Unlock()
	if closedPresent || !otherPresent {
		t.Fatal("closed stat state resurrected or unrelated state removed")
	}
}

func TestProcStatStatePrunesStaleViewsOnSchedule(t *testing.T) {
	now := time.Now()
	procStatStatesMu.Lock()
	previousStates, previousPrune := procStatStates, procStatNextPrune
	procStatStates = map[string]*procStatState{
		"stale": {lastSeen: now.Add(-procStatStateStaleAfter - time.Second)},
		"fresh": {lastSeen: now},
	}
	procStatNextPrune = now.Add(time.Minute)
	procStatStatesMu.Unlock()
	t.Cleanup(func() {
		procStatStatesMu.Lock()
		procStatStates, procStatNextPrune = previousStates, previousPrune
		procStatStatesMu.Unlock()
	})

	req := &domain.HandlerRequest{}
	procStatStateForKey(req, "fresh", now)
	procStatStatesMu.Lock()
	_, stillPresent := procStatStates["stale"]
	procStatStatesMu.Unlock()
	if !stillPresent {
		t.Fatal("pruned stale views on an ordinary lookup")
	}
	procStatStateForKey(req, "fresh", now.Add(time.Minute))
	procStatStatesMu.Lock()
	_, stalePresent := procStatStates["stale"]
	_, freshPresent := procStatStates["fresh"]
	procStatStatesMu.Unlock()
	if stalePresent || !freshPresent {
		t.Fatal("scheduled prune removed the wrong views")
	}
}
