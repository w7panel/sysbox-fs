package main

import (
	"sync"
	"testing"

	"github.com/nestybox/sysbox-fs/state"
)

func TestRecoveryForgetsDeadCheckpointOwners(t *testing.T) {
	r := &recoveryRunner{records: map[uint32][]state.RestartContainer{
		1: {{ID: "dead"}, {ID: "live"}},
		2: {{ID: "dead"}},
	}}
	r.fallbackDone.Store("dead", struct{}{})
	r.forgetRecords(map[string]bool{"dead": true})
	if got := r.checkpointContainers(); len(got) != 1 || got[0].ID != "live" {
		t.Fatalf("checkpoint containers after unregister: %+v", got)
	}
	if got := r.recordOwners(1); len(got) != 1 || got[0].ID != "live" {
		t.Fatalf("shared device owners after unregister: %+v", got)
	}
	if got := r.recordOwners(2); len(got) != 0 {
		t.Fatalf("dead device still has owners: %+v", got)
	}
	if _, ok := r.fallbackDone.Load("dead"); ok {
		t.Fatal("dead container remains marked as scanned")
	}
}

func TestRecoveryOwnersSurviveConcurrentPrune(t *testing.T) {
	r := &recoveryRunner{records: map[uint32][]state.RestartContainer{
		1: {{ID: "dead"}, {ID: "live"}},
	}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = r.recordOwners(1)
			_ = r.checkpointContainers()
		}
	}()
	r.forgetRecords(map[string]bool{"dead": true})
	wg.Wait()
}
