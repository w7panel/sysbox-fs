package seccomp

import (
	"sync"
	"testing"
)

func TestSeccompNotifPidTrackerCleansPidAfterConcurrentUse(t *testing.T) {
	tracker := newSeccompNotifPidTracker()
	pid := uint32(1001)
	const goroutines = 8
	started := make(chan struct{}, goroutines)
	release := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.Lock(pid)
			started <- struct{}{}
			<-release
			tracker.Unlock(pid)
		}()
	}

	<-started
	assertNoEvent(t, started, "same-pid tracker allowed overlapping locks")
	close(release)
	wg.Wait()

	tracker.mu.RLock()
	_, ok := tracker.pidTable[pid]
	tracker.mu.RUnlock()
	if ok {
		t.Fatal("pid tracker entry should be removed after all locks are released")
	}
}
