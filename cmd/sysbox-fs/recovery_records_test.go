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
	r.silentDone = map[string]map[uint64]bool{"dead": {10: true}, "live": {20: true}}
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
	if _, ok := r.silentDone["dead"]; ok {
		t.Fatal("dead container retains nested namespaces")
	}
	if !r.silentDone["live"][20] {
		t.Fatal("live container lost nested namespace")
	}
}

func TestRecoveryPrunesExitedNestedNamespaces(t *testing.T) {
	r := &recoveryRunner{silentDone: map[string]map[uint64]bool{
		"ckm": {10: true, 20: true},
	}}
	r.pruneSilentNamespaces("ckm", map[uint64]uint32{20: 200, 30: 300})
	if len(r.silentDone["ckm"]) != 1 || !r.silentDone["ckm"][20] {
		t.Fatalf("stale namespace retained or live namespace lost: %+v", r.silentDone["ckm"])
	}
	r.pruneSilentNamespaces("ckm", map[uint64]uint32{})
	if _, ok := r.silentDone["ckm"]; ok {
		t.Fatal("empty container namespace set retained")
	}
}

func TestRecoveryPrunesOnlyInactiveRepairedMountsAfterCompleteScan(t *testing.T) {
	r := &recoveryRunner{}
	exited := faultMount{10, 1}
	shared := faultMount{20, 1}
	deadOwner := faultMount{30, 2}
	live := faultMount{40, 3}
	for _, key := range []faultMount{exited, shared, deadOwner, live} {
		r.repaired.Store(key, struct{}{})
	}
	active := map[faultMount]bool{shared: true, live: true}
	r.pruneRepaired(active, false) // One live owner could not be enumerated.
	for _, key := range []faultMount{exited, shared, deadOwner, live} {
		if _, ok := r.repaired.Load(key); !ok {
			t.Fatalf("incomplete scan removed mount %+v", key)
		}
	}
	r.pruneRepaired(active, true)
	for _, key := range []faultMount{exited, deadOwner} {
		if _, ok := r.repaired.Load(key); ok {
			t.Fatalf("inactive mount retained: %+v", key)
		}
	}
	for _, key := range []faultMount{shared, live} {
		if _, ok := r.repaired.Load(key); !ok {
			t.Fatalf("live shared mount removed: %+v", key)
		}
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
