package implementations

import (
	"bytes"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

func TestReadOnlyResourceSnapshotPrunesExpiredUnrelatedEntries(t *testing.T) {
	now := time.Now()
	currentKey := "/proc/test:pid:1001"
	staleKey := "/proc/test:pid:1002"
	freshKey := "/proc/test:pid:1003"
	h := newReadOnlyResource("ProcTest", "/proc/test", func(req *domain.HandlerRequest) ([]byte, error) {
		t.Fatal("read callback called for fresh current snapshot")
		return nil, nil
	})
	h.snapshots[currentKey] = resourceSnapshot{data: []byte("current"), createdAt: now.Add(-resourceSnapshotTTL / 2)}
	h.snapshots[staleKey] = resourceSnapshot{data: []byte("stale"), createdAt: now.Add(-resourceSnapshotTTL * 2)}
	h.snapshots[freshKey] = resourceSnapshot{data: []byte("fresh"), createdAt: now.Add(-resourceSnapshotTTL / 2)}

	data, err := h.snapshotData(&domain.HandlerRequest{Pid: 1001})
	if err != nil {
		t.Fatalf("snapshotDataAt() error = %v", err)
	}
	if !bytes.Equal(data, []byte("current")) {
		t.Fatalf("snapshotDataAt() = %q, want current", data)
	}
	if _, ok := h.snapshots[staleKey]; ok {
		t.Fatalf("stale snapshot %q still present", staleKey)
	}
	if _, ok := h.snapshots[freshKey]; !ok {
		t.Fatalf("fresh snapshot %q removed", freshKey)
	}
	if _, ok := h.snapshots[currentKey]; !ok {
		t.Fatalf("current snapshot %q removed", currentKey)
	}
}

func TestReadOnlyResourceSnapshotPreservesExpiredCurrentEntryForNonZeroOffset(t *testing.T) {
	now := time.Now()
	currentKey := "/proc/test:pid:2001"
	staleKey := "/proc/test:pid:2002"
	h := newReadOnlyResource("ProcTest", "/proc/test", func(req *domain.HandlerRequest) ([]byte, error) {
		t.Fatal("read callback called for non-zero offset snapshot")
		return nil, nil
	})
	h.snapshots[currentKey] = resourceSnapshot{data: []byte("current"), createdAt: now.Add(-resourceSnapshotTTL * 2)}
	h.snapshots[staleKey] = resourceSnapshot{data: []byte("stale"), createdAt: now.Add(-resourceSnapshotTTL * 2)}

	data, err := h.snapshotData(&domain.HandlerRequest{Pid: 2001, Offset: 1})
	if err != nil {
		t.Fatalf("snapshotDataAt() error = %v", err)
	}
	if !bytes.Equal(data, []byte("current")) {
		t.Fatalf("snapshotDataAt() = %q, want current", data)
	}
	if _, ok := h.snapshots[staleKey]; ok {
		t.Fatalf("stale snapshot %q still present", staleKey)
	}
	if _, ok := h.snapshots[currentKey]; !ok {
		t.Fatalf("current snapshot %q removed", currentKey)
	}
}

func TestProcUptimeSnapshotPrunesExpiredUnrelatedEntries(t *testing.T) {
	resetProcUptimeSnapshots(t)
	now := time.Date(2026, 6, 27, 13, 0, 0, 0, time.UTC)
	currentKey := "pid:3001"
	staleKey := "pid:3002"
	procUptimeSnapshots.entries[currentKey] = procUptimeSnapshot{data: []byte("1.00 1.00\n"), createdAt: now.Add(-procUptimeSnapshotTTL / 2)}
	procUptimeSnapshots.entries[staleKey] = procUptimeSnapshot{data: []byte("0.00 0.00\n"), createdAt: now.Add(-procUptimeSnapshotTTL * 2)}

	data := procUptimeData(&domain.HandlerRequest{Pid: 3001}, now.Add(-time.Second), now)
	if !bytes.Equal(data, []byte("1.00 1.00\n")) {
		t.Fatalf("procUptimeData() = %q, want cached current data", data)
	}
	if _, ok := procUptimeSnapshots.entries[staleKey]; ok {
		t.Fatalf("stale uptime snapshot %q still present", staleKey)
	}
	if _, ok := procUptimeSnapshots.entries[currentKey]; !ok {
		t.Fatalf("current uptime snapshot %q removed", currentKey)
	}
}

func TestProcUptimeSnapshotPreservesExpiredCurrentEntryForNonZeroOffset(t *testing.T) {
	resetProcUptimeSnapshots(t)
	now := time.Date(2026, 6, 27, 13, 0, 0, 0, time.UTC)
	currentKey := "pid:4001"
	staleKey := "pid:4002"
	procUptimeSnapshots.entries[currentKey] = procUptimeSnapshot{data: []byte("2.00 2.00\n"), createdAt: now.Add(-procUptimeSnapshotTTL * 2)}
	procUptimeSnapshots.entries[staleKey] = procUptimeSnapshot{data: []byte("0.00 0.00\n"), createdAt: now.Add(-procUptimeSnapshotTTL * 2)}

	data := procUptimeData(&domain.HandlerRequest{Pid: 4001, Offset: 1}, now.Add(-time.Second), now)
	if !bytes.Equal(data, []byte("2.00 2.00\n")) {
		t.Fatalf("procUptimeData() = %q, want cached current data", data)
	}
	if _, ok := procUptimeSnapshots.entries[staleKey]; ok {
		t.Fatalf("stale uptime snapshot %q still present", staleKey)
	}
	if _, ok := procUptimeSnapshots.entries[currentKey]; !ok {
		t.Fatalf("current uptime snapshot %q removed", currentKey)
	}
}

func resetProcUptimeSnapshots(t *testing.T) {
	t.Helper()
	procUptimeSnapshots.Lock()
	original := procUptimeSnapshots.entries
	procUptimeSnapshots.entries = make(map[string]procUptimeSnapshot)
	procUptimeSnapshots.Unlock()
	t.Cleanup(func() {
		procUptimeSnapshots.Lock()
		procUptimeSnapshots.entries = original
		procUptimeSnapshots.Unlock()
	})
}
