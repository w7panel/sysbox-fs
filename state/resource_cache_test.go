package state

import (
	"testing"
	"time"
)

func TestResourceCachePolicyDuringMountInitialization(t *testing.T) {
	c := &container{}
	c.SetResourceCacheTTL(25 * time.Millisecond)
	// InitializeMountInfo holds this lock while a namespace helper may read FUSE.
	c.intLock.Lock()
	done := make(chan time.Duration, 1)
	go func() { done <- c.ResourceCacheTTL() }()
	select {
	case ttl := <-done:
		c.intLock.Unlock()
		if ttl != 25*time.Millisecond {
			t.Fatalf("TTL = %s", ttl)
		}
	case <-time.After(time.Second):
		c.intLock.Unlock()
		<-done
		t.Fatal("FUSE cache policy blocks on mount initialization")
	}
}
