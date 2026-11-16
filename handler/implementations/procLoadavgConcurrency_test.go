package implementations

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
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
		sample: func(int) (int, int, int) {
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
		sample: func(int) (int, int, int) {
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
		sample: func(int) (int, int, int) { sampled <- struct{}{}; return 1, 1, 42 },
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
	s := &loadavgSamplerState{sample: func(pid int) (int, int, int) {
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

func TestLoadavgLazyOwnerSampler(t *testing.T) {
	owner := &domain.ResourceOwner{ID: 903}
	req := &domain.HandlerRequest{ResourceOwner: owner}
	t.Cleanup(func() { ReleaseResourceOwner(owner) })
	first := loadavgSamplerForReq(req)
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
	sampler := &loadavgSamplerState{nodes: map[string]*loadavgNode{"view": node}, sample: func(int) (int, int, int) { calls++; return 1, 1, 1 }}
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
	s := &loadavgSamplerState{nodes: map[string]*loadavgNode{"old-view": node}, sample: func(int) (int, int, int) { t.Fatal("sampled changed cgroup"); return 0, 0, 0 }}
	s.refresh(node)
	if !node.closed || len(s.nodes) != 0 {
		t.Fatal("old cgroup sampler retained")
	}
}
