package implementations

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	sysio "github.com/nestybox/sysbox-fs/sysio"
)

func TestByteSnapshotsTTLAndContinuation(t *testing.T) {
	for _, ttl := range []time.Duration{resourceSnapshotTTL, procUptimeSnapshotTTL} {
		t.Run(ttl.String(), func(t *testing.T) {
			var cache byteSnapshots
			now := time.Now()
			reads := 0
			read := func() ([]byte, error) { reads++; return []byte(fmt.Sprint(reads)), nil }
			get := func(key string, offset bool, at time.Time) string {
				data, err := cache.get(key, "owner", nil, offset, at, ttl, read)
				if err != nil {
					t.Fatal(err)
				}
				return string(data)
			}
			if get("current", false, now) != "1" || get("current", false, now.Add(ttl/2)) != "1" {
				t.Fatal("fresh data was not reused")
			}
			get("unrelated", false, now)
			if get("current", true, now.Add(2*ttl)) != "1" {
				t.Fatal("continuation refreshed expired data")
			}
			if get("current", false, now.Add(2*ttl)) != "3" {
				t.Fatal("expired data was not refreshed")
			}
			if _, ok := cache.entries["unrelated"]; !ok {
				t.Fatal("full-table cleanup ran before the prune interval")
			}
			get("trigger", false, now.Add(time.Minute))
			if _, ok := cache.entries["unrelated"]; ok {
				t.Fatal("expired unrelated data retained after prune interval")
			}
		})
	}
}

func TestByteSnapshotsConcurrentRefresh(t *testing.T) {
	var cache byteSnapshots
	var reads atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	read := func() ([]byte, error) {
		if reads.Add(1) == 1 {
			close(entered)
		}
		<-release
		return []byte("data"), nil
	}
	var wg sync.WaitGroup
	now := time.Now()
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := cache.get("key", "owner", nil, false, now, time.Second, read)
			if err != nil || string(data) != "data" {
				t.Errorf("get = %q, %v", data, err)
			}
		}()
	}
	<-entered
	// An unrelated key must finish while the first key's collector is blocked.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := cache.get("other", "owner", nil, false, now, time.Second, func() ([]byte, error) { return []byte("other"), nil })
		if err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("unrelated refresh blocked")
	}
	close(release)
	wg.Wait()
	if reads.Load() != 1 {
		t.Fatalf("collector called %d times", reads.Load())
	}
}

func TestByteSnapshotsErrorRetry(t *testing.T) {
	var cache byteSnapshots
	now := time.Now()
	want := errors.New("collection failed")
	if _, err := cache.get("key", "owner", nil, false, now, time.Second, func() ([]byte, error) { return nil, want }); err != want {
		t.Fatalf("error = %v", err)
	}
	data, err := cache.get("key", "owner", nil, false, now, time.Second, func() ([]byte, error) { return []byte("retry"), nil })
	if err != nil || string(data) != "retry" {
		t.Fatalf("retry = %q, %v", data, err)
	}
}

func TestCgroupViewKey(t *testing.T) {
	a := cgroupView{v1: map[string]string{"cpu": "/a", "memory": "/b"}}
	b := cgroupView{v1: map[string]string{"memory": "/b", "cpu": "/a"}}
	if cgroupViewKey(a) != cgroupViewKey(b) {
		t.Fatal("controller map order changes key")
	}
	b.v1["memory"] = "/c"
	if cgroupViewKey(a) == cgroupViewKey(b) {
		t.Fatal("v1 views collide")
	}
	if cgroupViewKey(cgroupView{v2Path: "/a"}) == cgroupViewKey(cgroupView{v2Path: "/b"}) {
		t.Fatal("v2 views collide")
	}
}

func TestResourceViewKeyIsolation(t *testing.T) {
	a := &domain.HandlerRequest{Pid: uint32(os.Getpid()), ResourceOwner: &domain.ResourceOwner{ID: 1}}
	b := &domain.HandlerRequest{Pid: a.Pid, ResourceOwner: &domain.ResourceOwner{ID: 2}}
	if resourceViewKey(a) == resourceViewKey(b) {
		t.Fatal("different lifetimes share data")
	}
	a = &domain.HandlerRequest{Pid: ^uint32(0), ResourceOwner: a.ResourceOwner}
	b = &domain.HandlerRequest{Pid: ^uint32(0) - 1, ResourceOwner: a.ResourceOwner}
	if resourceViewKey(a) == resourceViewKey(b) {
		t.Fatal("unresolved processes share data")
	}
}

func TestReadOnlyResourcePartialRead(t *testing.T) {
	h := newReadOnlyResource("Test", "/proc/snapshot-test", func(*domain.HandlerRequest) ([]byte, error) { return []byte("abcdef"), nil })
	req := &domain.HandlerRequest{Pid: ^uint32(0), Data: make([]byte, 3)}
	node := sysio.NewIOService(domain.IOOsFileService).NewIOnode("snapshot-test", h.Path, 0444)
	defer h.snapshots.release(resourceOwnerKey(req))
	n, err := h.Read(node, req)
	if n != 3 || err != nil || string(req.Data) != "abc" {
		t.Fatalf("initial = %q, %v", req.Data, err)
	}
	req.Offset = 3
	n, err = h.Read(node, req)
	if n != 3 || err != nil || string(req.Data) != "def" {
		t.Fatalf("continuation = %q, %v", req.Data, err)
	}
	req.Offset = 6
	if _, err = h.Read(node, req); err != io.EOF {
		t.Fatalf("end = %v", err)
	}
}

func BenchmarkByteSnapshotsParallelHit(b *testing.B) {
	var cache byteSnapshots
	now := time.Now()
	read := func() ([]byte, error) { return []byte("data"), nil }
	cache.get("key", "owner", nil, false, now, time.Second, read)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.get("key", "owner", nil, false, now, time.Second, read)
		}
	})
}

func TestByteSnapshotsReleaseDuringRefresh(t *testing.T) {
	var cache byteSnapshots
	owner := &domain.ResourceOwner{ID: 31}
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	now := time.Now()
	cache.get("existing", "owner:31", owner, false, now, time.Second, func() ([]byte, error) { return []byte("cached"), nil })
	cache.get("other", "owner:32", nil, false, now, time.Second, func() ([]byte, error) { return []byte("other"), nil })
	go func() {
		_, err := cache.get("inflight", "owner:31", owner, false, now, time.Second, func() ([]byte, error) { close(entered); <-resume; return []byte("late"), nil })
		done <- err
	}()
	<-entered
	owner.Close()
	cache.release("owner:31")
	close(resume)
	if err := <-done; !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inflight = %v", err)
	}
	if len(cache.entries) != 1 || string(cache.entries["other"].data) != "other" {
		t.Fatalf("release retained or removed wrong entries: %v", cache.entries)
	}
	_, err := cache.get("late", "owner:31", owner, false, now, time.Second, func() ([]byte, error) { t.Fatal("closed owner collected"); return nil, nil })
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed owner = %v", err)
	}
}

func TestProcUptimeSnapshotReuse(t *testing.T) {
	req := &domain.HandlerRequest{Pid: uint32(os.Getpid()), ResourceOwner: &domain.ResourceOwner{ID: 9981}}
	defer procUptimeSnapshots.release(resourceOwnerKey(req))
	now := time.Now()
	initial, err := procUptimeData(req, now.Add(-time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := procUptimeData(req, now, now.Add(procUptimeSnapshotTTL/2))
	if err != nil || string(cached) != string(initial) {
		t.Fatalf("cached uptime = %q, %v; want %q", cached, err, initial)
	}
	req.Offset = 1
	continued, err := procUptimeData(req, now, now.Add(2*procUptimeSnapshotTTL))
	if err != nil || string(continued) != string(initial) {
		t.Fatalf("continued uptime = %q, %v; want %q", continued, err, initial)
	}
	req.Offset = 0
	refreshed, err := procUptimeData(req, now, now.Add(2*procUptimeSnapshotTTL))
	if err != nil || string(refreshed) == string(initial) {
		t.Fatalf("uptime did not refresh: %q, %v", refreshed, err)
	}
}

func TestByteSnapshotsNestedViewIsolation(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			var cache byteSnapshots
			req := &domain.HandlerRequest{ResourceOwner: &domain.ResourceOwner{ID: 400}}
			owner := resourceOwnerKey(req)
			now := time.Now()
			for _, view := range []struct{ path, ns string }{{"/inner-a", "pid:[1]"}, {"/inner-b", "pid:[1]"}, {"/inner-a", "pid:[2]"}} {
				cg := cgroupView{v2Path: view.path}
				if version == "v1" {
					cg = cgroupView{v1: map[string]string{"cpu": view.path, "memory": view.path}}
				}
				key := resourceViewKeyFor(req, cg, view.ns)
				want := view.path + view.ns
				data, err := cache.get(key, owner, req.ResourceOwner, false, now, time.Second, func() ([]byte, error) { return []byte(want), nil })
				if err != nil || string(data) != want {
					t.Fatalf("view %s: data=%q, err=%v", want, data, err)
				}
			}
			if len(cache.entries) != 3 {
				t.Fatalf("views share entries: %d", len(cache.entries))
			}
		})
	}
}

func BenchmarkByteSnapshotsParallelHit1000(b *testing.B) {
	var cache byteSnapshots
	now := time.Now()
	read := func() ([]byte, error) { return []byte("data"), nil }
	for i := 0; i < 1000; i++ {
		cache.get(fmt.Sprint(i), "owner", nil, false, now, time.Second, read)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.get("0", "owner", nil, false, now, time.Second, read)
		}
	})
}

func BenchmarkByteSnapshotsManyViews(b *testing.B) {
	var cache byteSnapshots
	now := time.Now()
	read := func() ([]byte, error) { return []byte("data"), nil }
	keys := make([]string, 1000)
	for i := range keys {
		keys[i] = fmt.Sprint(i)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		now = now.Add(time.Millisecond)
		if _, err := cache.get(keys[i%len(keys)], "owner", nil, false, now, resourceSnapshotTTL, read); err != nil {
			b.Fatal(err)
		}
	}
}

func TestResourceSnapshotContinuationSurvivesOtherResourcePrune(t *testing.T) {
	req := &domain.HandlerRequest{Pid: ^uint32(0), Offset: 1}
	stat := newReadOnlyResource("Stat", "/proc/stat", func(*domain.HandlerRequest) ([]byte, error) { t.Fatal("stat continuation refreshed"); return nil, nil })
	mem := newReadOnlyResource("Mem", "/proc/meminfo", func(*domain.HandlerRequest) ([]byte, error) { return []byte("mem"), nil })
	key := resourceViewKey(req)
	stat.snapshots.entries = map[string]resourceSnapshot{key: {data: []byte("old stat"), createdAt: time.Now().Add(-2 * resourceSnapshotTTL)}}
	if _, err := mem.snapshotData(req); err != nil {
		t.Fatal(err)
	}
	data, err := stat.snapshotData(req)
	if err != nil || string(data) != "old stat" {
		t.Fatalf("continuation = %q, %v", data, err)
	}
}
