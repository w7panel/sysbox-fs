package implementations

import (
	"errors"
	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/sysio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGlobalCacheConcurrentRefresh(t *testing.T) {
	var cache byteSnapshots
	var calls atomic.Int32
	now := time.Now()
	read := func() ([]byte, error) {
		calls.Add(1)
		return []byte("host"), nil
	}
	for _, at := range []time.Time{now, now.Add(globalCacheTTL - time.Nanosecond), now.Add(globalCacheTTL)} {
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				data, err := cache.get("cpuinfo", "", nil, false, at, globalCacheTTL, read)
				if err != nil || string(data) != "host" {
					t.Errorf("read: %q, %v", data, err)
				}
			}()
		}
		wg.Wait()
	}
	if calls.Load() != 2 {
		t.Fatalf("expected one collection per TTL, got %d", calls.Load())
	}
}

func TestGlobalCacheReadFailureRetries(t *testing.T) {
	var cache byteSnapshots
	now := time.Now()
	want := errors.New("unavailable")
	_, err := cache.get("host", "", nil, false, now, globalCacheTTL, func() ([]byte, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Fatalf("error = %v", err)
	}
	data, err := cache.get("host", "", nil, false, now, globalCacheTTL, func() ([]byte, error) { return []byte("recovered"), nil })
	if err != nil || string(data) != "recovered" {
		t.Fatalf("retry: %q, %v", data, err)
	}
}

func TestGlobalCPUInputKeepsViewsIsolated(t *testing.T) {
	host := []byte("processor\t: 0\nmodel name\t: first\n\nprocessor\t: 1\nmodel name\t: second\n")
	original := string(host)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(cpu int) {
			defer wg.Done()
			set, model := "0", "first"
			if cpu%2 != 0 {
				set, model = "1", "second"
			}
			view := string(cpuInfoFromHost(host, set, 1))
			if !strings.Contains(view, model) || strings.Count(view, "processor") != 1 {
				t.Errorf("view for %s: %s", set, view)
			}
		}(i)
	}
	wg.Wait()
	if string(host) != original {
		t.Fatal("container view mutated shared host input")
	}
}

func TestGlobalKernelVersionReadWithoutNSenter(t *testing.T) {
	for _, path := range []string{"/proc/sys/kernel/ostype", "/proc/sys/kernel/osrelease", "/proc/sys/kernel/version"} {
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		node := sysio.NewIOService(domain.IOOsFileService).NewIOnode(filepath.Base(path), path, 0444)
		h := &PassThrough{}
		req := &domain.HandlerRequest{Data: make([]byte, len(want))}
		n, err := h.Read(node, req)
		if err != nil || string(req.Data[:n]) != string(want) {
			t.Fatalf("%s: %q, %v", path, req.Data[:n], err)
		}
		req.Offset = int64(n)
		if n, err := h.Read(node, req); n != 0 || err != io.EOF {
			t.Fatalf("%s EOF: %d, %v", path, n, err)
		}
	}
}

func TestPruneCgroupDoesNotMutateRequestIdentity(t *testing.T) {
	raw := cgroupView{v1: map[string]string{"cpu": "/container/init.scope", "memory": "/container"}}
	pruned := pruneInitScopeCgroup(raw)
	if pruned.v1["cpu"] != "/container" || raw.v1["cpu"] != "/container/init.scope" {
		t.Fatalf("pruned %#v changed original %#v", pruned, raw)
	}
}
