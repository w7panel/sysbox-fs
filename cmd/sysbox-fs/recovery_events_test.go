package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/recovery"
)

type testFaultEvents struct {
	faults chan recovery.Fault
	closed chan struct{}
	once   sync.Once
}

func (e *testFaultEvents) Read() (recovery.Fault, error) {
	select {
	case fault := <-e.faults:
		return fault, nil
	case <-e.closed:
		return recovery.Fault{}, io.EOF
	}
}

func (e *testFaultEvents) Close() error {
	e.once.Do(func() { close(e.closed) })
	return nil
}

func TestRecoveryEventsContinueWhileRepairBlocks(t *testing.T) {
	events := &testFaultEvents{faults: make(chan recovery.Fault, 400), closed: make(chan struct{})}
	r := &recoveryRunner{events: events, faultCounts: make(map[faultProcess]int)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.runEvents(ctx, func(ctx context.Context, fault recovery.Fault) {
			select {
			case <-started:
			default:
				close(started)
			}
			<-release
		})
	}()
	events.faults <- recovery.Fault{PID: 1, Namespace: 1, Device: 1}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("repair did not start")
	}
	// More distinct faults than the queue can hold must not block event reads.
	for i := 0; i < 300; i++ {
		events.faults <- recovery.Fault{PID: 1, Namespace: uint64(i + 2), Device: 1}
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		var metrics bytes.Buffer
		r.writeMetrics(&metrics)
		if strings.Contains(metrics.String(), "sysbox_fs_recovery_fault_events_total 301\n") &&
			strings.Contains(metrics.String(), "sysbox_fs_recovery_dropped_fault_events_total 44\n") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("event reader blocked behind slow repair or full queue")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
}

func TestRecoveryEventsDeduplicatePendingMount(t *testing.T) {
	events := &testFaultEvents{faults: make(chan recovery.Fault, 20), closed: make(chan struct{})}
	r := &recoveryRunner{events: events, faultCounts: make(map[faultProcess]int)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	var handled int
	var mu sync.Mutex
	done := make(chan error, 1)
	go func() {
		done <- r.runEvents(ctx, func(ctx context.Context, fault recovery.Fault) {
			mu.Lock()
			handled++
			mu.Unlock()
			if fault.Namespace == 1 {
				close(started)
				<-release
			}
		})
	}()
	fault := recovery.Fault{PID: 1, Namespace: 1, Device: 1}
	events.faults <- fault
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("repair did not start")
	}
	for i := 0; i < 10; i++ {
		events.faults <- fault
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.statsMu.Lock()
		count := r.faultEvents
		r.statsMu.Unlock()
		if count == 11 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("duplicate events were not counted")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop")
	}
	mu.Lock()
	defer mu.Unlock()
	if handled != 1 {
		t.Fatalf("duplicate mount repairs: %d", handled)
	}
}
