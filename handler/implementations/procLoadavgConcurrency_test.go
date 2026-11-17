package implementations

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

func TestLoadavgConcurrentRefresh(t *testing.T) {
	node := &loadavgNode{}
	started, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := &loadavgSamplerState{
		nodes: map[string]*loadavgNode{"node": node},
		sample: func(int, cgroupView, string) (int, int, int) {
			calls.Add(1)
			close(started)
			<-finish
			return 3, 2, 42
		},
	}
	done := make(chan struct{})
	go func() { s.refresh(node); close(done) }()
	<-started
	var readers sync.WaitGroup
	for i := 0; i < 32; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			s.refresh(node)
			node.format()
		}()
	}
	readers.Wait()
	close(finish)
	<-done
	if calls.Load() != 1 || node.avenrun[0] != calcLoadavg(0, loadavgExp1, 2) {
		t.Fatalf("refresh calls=%d, load=%d", calls.Load(), node.avenrun[0])
	}
}

func TestLoadavgReleaseDuringRefresh(t *testing.T) {
	node := &loadavgNode{owner: "old"}
	other := &loadavgNode{owner: "other"}
	started, finish := make(chan struct{}), make(chan struct{})
	s := &loadavgSamplerState{
		nodes: map[string]*loadavgNode{"old": node, "other": other},
		sample: func(int, cgroupView, string) (int, int, int) {
			close(started)
			<-finish
			return 3, 2, 42
		},
	}
	done := make(chan struct{})
	go func() { s.refresh(node); close(done) }()
	<-started
	s.release("old")
	close(finish)
	<-done
	if !node.closed || node.avenrun != [3]uint64{} {
		t.Fatal("released node accepted an in-flight sample")
	}
	if len(s.nodes) != 1 || s.nodes["other"] != other || other.closed {
		t.Fatal("release removed another owner")
	}
}

func TestLoadavgSamplerLifetime(t *testing.T) {
	node := &loadavgNode{owner: "owner", stop: make(chan struct{})}
	sampled := make(chan struct{}, 1)
	s := &loadavgSamplerState{
		nodes:  map[string]*loadavgNode{"node": node},
		sample: func(int, cgroupView, string) (int, int, int) { sampled <- struct{}{}; return 1, 1, 42 },
	}
	done := make(chan struct{})
	go func() { s.run(node); close(done) }()
	t.Cleanup(func() { s.release("owner") })
	select {
	case <-sampled:
		t.Fatal("sampled before the first interval")
	case <-time.After(20 * time.Millisecond):
	}
	// Sampling continues without reads, and cancellation does not wait for a tick.
	select {
	case <-sampled:
	case <-time.After(loadavgSampleInterval + time.Second):
		t.Fatal("sampler did not run")
	}
	s.release("owner")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sampler did not exit on release")
	}
}

func BenchmarkLoadavgConcurrentRead(b *testing.B) {
	node := &loadavgNode{total: 3, lastPID: 42}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			node.format()
		}
	})
}

func TestLoadavgIndependentNodeRefresh(t *testing.T) {
	first := &loadavgNode{samplePID: 1}
	second := &loadavgNode{samplePID: 2}
	started, finish := make(chan struct{}), make(chan struct{})
	s := &loadavgSamplerState{sample: func(pid int, _ cgroupView, _ string) (int, int, int) {
		if pid == 1 {
			close(started)
			<-finish
		}
		return 1, 1, pid
	}}
	done := make(chan struct{})
	go func() { s.refresh(first); close(done) }()
	<-started
	s.refresh(second)
	if second.lastPID != 2 {
		t.Error("unrelated node did not refresh")
	}
	close(finish)
	<-done
}

func TestLoadavgSamplerUsesRequestViewNotAnchorCgroup(t *testing.T) {
	view := cgroupView{v2Path: "/nested/pod"}
	node := &loadavgNode{samplePID: 123, viewCgroup: view, pidns: "pid:[7]"}
	s := &loadavgSamplerState{sample: func(pid int, cg cgroupView, ns string) (int, int, int) {
		if pid != 123 || cg.v2Path != view.v2Path || ns != "pid:[7]" {
			t.Fatalf("sampled anchor instead of request view: %d, %#v, %q", pid, cg, ns)
		}
		return 2, 1, 9
	}}
	s.refresh(node)
	if node.lastPID != 9 {
		t.Fatal("request view was not sampled")
	}
}

func TestLoadavgLazyOwnerSampler(t *testing.T) {
	owner := &domain.ResourceOwner{ID: 903}
	req := &domain.HandlerRequest{ResourceOwner: owner}
	t.Cleanup(func() { ReleaseResourceOwner(owner) })
	first := loadavgSamplerForReq(req)
	if first.lastPID == 0 {
		t.Fatal("first loadavg read has no namespace PID seed")
	}
	if first != loadavgSamplerForReq(req) {
		t.Fatal("repeated read created another sampler")
	}
	otherOwner := &domain.ResourceOwner{ID: 904}
	t.Cleanup(func() { ReleaseResourceOwner(otherOwner) })
	other := loadavgSamplerForReq(&domain.HandlerRequest{ResourceOwner: otherOwner})
	if first == other {
		t.Fatal("distinct owners share a sampler")
	}
	ReleaseResourceOwner(owner)
	select {
	case <-first.stop:
	default:
		t.Fatal("release did not cancel the sampler")
	}
	closed := loadavgSamplerForReq(req)
	if !closed.closed || closed.stop != nil {
		t.Fatal("closed owner restarted sampling")
	}
	other.RLock()
	defer other.RUnlock()
	if other.closed {
		t.Fatal("release stopped another owner")
	}
}

func TestLoadavgExitedPIDStopsSampler(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	pid := cmd.Process.Pid
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		t.Fatal(err)
	}
	node := &loadavgNode{key: "view", cgroupKey: cgroupViewKey(pruneInitScopeCgroup(cgroupForPid(uint32(pid)))), samplePID: pid, pidfd: os.NewFile(uintptr(fd), "pid"), pidns: ns, stop: make(chan struct{})}
	calls := 0
	sampler := &loadavgSamplerState{nodes: map[string]*loadavgNode{"view": node}, sample: func(int, cgroupView, string) (int, int, int) { calls++; return 1, 1, 1 }}
	sampler.refresh(node)
	if calls != 1 {
		t.Fatal("live process not sampled")
	}
	cmd.Process.Kill()
	cmd.Wait()
	sampler.refresh(node)
	if calls != 1 || !node.closed || len(sampler.nodes) != 0 {
		t.Fatal("exited process was sampled or retained")
	}
	if total, running, last := loadavgStatsForPID(pid); total != 0 || running != 0 || last != 0 {
		t.Fatal("exited process fell back to host statistics")
	}
}

func TestLoadavgCgroupChangeInvalidatesSampler(t *testing.T) {
	pid := os.Getpid()
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		t.Fatal(err)
	}
	node := &loadavgNode{key: "old-view", samplePID: pid, pidfd: os.NewFile(uintptr(fd), "pid"), pidns: ns, cgroupKey: "old-cgroup", stop: make(chan struct{})}
	s := &loadavgSamplerState{nodes: map[string]*loadavgNode{"old-view": node}, sample: func(int, cgroupView, string) (int, int, int) { t.Fatal("sampled changed cgroup"); return 0, 0, 0 }}
	s.refresh(node)
	if !node.closed || len(s.nodes) != 0 {
		t.Fatal("old cgroup sampler retained")
	}
}

func TestLoadavgViewKeySeparatesPIDNamespaces(t *testing.T) {
	cg := cgroupView{v2Path: "/pod"}
	first := loadavgViewKey(cg, "pid:[1]")
	if first == loadavgViewKey(cg, "pid:[2]") {
		t.Fatal("different PID namespaces share a sampler")
	}
	if first != loadavgViewKey(cg, "pid:[1]") {
		t.Fatal("same cgroup and PID namespace got different samplers")
	}
	if first == loadavgViewKey(cgroupView{v2Path: "/other-pod"}, "pid:[1]") {
		t.Fatal("different cgroups share a sampler")
	}
}

func TestLoadavgTaskStatsFiltersPIDNamespace(t *testing.T) {
	base := t.TempDir()
	for _, task := range []struct {
		pid, ns, nspid string
	}{
		{"101", "pid:[1]", "7"},
		{"202", "pid:[2]", "99"},
	} {
		dir := filepath.Join(base, task.pid, "task", task.pid)
		if err := os.MkdirAll(filepath.Join(dir, "ns"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte("State:\tR\nNSpid:\t"+task.nspid+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(task.ns, filepath.Join(dir, "ns", "pid")); err != nil {
			t.Fatal(err)
		}
	}
	total, running, lastPID, ok := loadavgTaskStats(map[int]struct{}{101: {}, 202: {}}, "pid:[1]", base)
	if !ok || total != 1 || running != 1 || lastPID != 7 {
		t.Fatalf("filtered stats = %d, %d, %d, %v", total, running, lastPID, ok)
	}
}

func TestLoadavgCgroupContainsOnlyDescendants(t *testing.T) {
	parent := cgroupView{v2Path: "/pod/child"}
	if !loadavgCgroupContains(parent, cgroupView{v2Path: "/pod/child/task"}) {
		t.Fatal("child cgroup omitted")
	}
	if loadavgCgroupContains(parent, cgroupView{v2Path: "/pod"}) {
		t.Fatal("parent cgroup included")
	}
}
