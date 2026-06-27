package seccomp

import (
	"sync"
	"testing"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func TestNotifSchedulerCapsConcurrentProcessing(t *testing.T) {
	scheduler := newNotifScheduler(2, newSeccompNotifPidTracker())
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	var mu sync.Mutex
	active := 0
	maxActive := 0

	processFn := func(req *sysRequest, fd int32, cntrID string) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		entered <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
	}

	for i := 0; i < 4; i++ {
		go scheduler.Schedule(&sysRequest{Pid: uint32(i + 1)}, 0, "c1", processFn)
	}
	<-entered
	<-entered
	assertNoEvent(t, entered, "scheduler allowed more than two concurrent notifications")

	close(release)
	<-entered
	<-entered
	scheduler.Wait()
	if maxActive != 2 {
		t.Fatalf("max active notifications = %d, want 2", maxActive)
	}
}

func TestNotifSchedulerReleasesSlotAfterProcessing(t *testing.T) {
	scheduler := newNotifScheduler(1, newSeccompNotifPidTracker())
	firstRelease := make(chan struct{})
	started := make(chan uint32, 2)

	processFn := func(req *sysRequest, fd int32, cntrID string) {
		started <- req.Pid
		if req.Pid == 1 {
			<-firstRelease
		}
	}

	scheduler.Schedule(&sysRequest{Pid: 1}, 0, "c1", processFn)
	<-started
	go scheduler.Schedule(&sysRequest{Pid: 2}, 0, "c1", processFn)
	assertNoEvent(t, started, "second notification started before first released limiter slot")

	close(firstRelease)
	if got := <-started; got != 2 {
		t.Fatalf("started pid = %d, want 2", got)
	}
	scheduler.Wait()
}

func TestNotifSchedulerSerializesSamePid(t *testing.T) {
	scheduler := newNotifScheduler(2, newSeccompNotifPidTracker())
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	var mu sync.Mutex
	active := 0
	maxActive := 0

	processFn := func(req *sysRequest, fd int32, cntrID string) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		started <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
	}

	go scheduler.Schedule(&sysRequest{Pid: 1001}, 0, "c1", processFn)
	go scheduler.Schedule(&sysRequest{Pid: 1001}, 0, "c1", processFn)
	<-started
	assertNoEvent(t, started, "same-pid notification overlapped")

	close(release)
	<-started
	scheduler.Wait()
	if maxActive != 1 {
		t.Fatalf("max active same-pid notifications = %d, want 1", maxActive)
	}
}

func TestNotifSchedulerAllowsDifferentPidsInParallel(t *testing.T) {
	scheduler := newNotifScheduler(2, newSeccompNotifPidTracker())
	release := make(chan struct{})
	started := make(chan uint32, 2)

	processFn := func(req *sysRequest, fd int32, cntrID string) {
		started <- req.Pid
		<-release
	}

	scheduler.Schedule(&sysRequest{Pid: 1001}, 0, "c1", processFn)
	scheduler.Schedule(&sysRequest{Pid: 1002}, 0, "c1", processFn)
	first := <-started
	second := <-started
	if first == second {
		t.Fatalf("expected two different pids, got %d and %d", first, second)
	}

	close(release)
	scheduler.Wait()
}

func TestNotifSchedulerReleasesSlotWhenProcessReturnsError(t *testing.T) {
	scheduler := newNotifScheduler(1, newSeccompNotifPidTracker())
	started := make(chan uint32, 2)

	processFn := func(req *sysRequest, fd int32, cntrID string) {
		started <- req.Pid
	}

	scheduler.Schedule(&sysRequest{Pid: 1, ID: 1, Data: libseccomp.ScmpNotifData{}}, 0, "c1", processFn)
	scheduler.Wait()
	scheduler.Schedule(&sysRequest{Pid: 2, ID: 2, Data: libseccomp.ScmpNotifData{}}, 0, "c1", processFn)
	scheduler.Wait()

	if got := <-started; got != 1 {
		t.Fatalf("first started pid = %d, want 1", got)
	}
	if got := <-started; got != 2 {
		t.Fatalf("second started pid = %d, want 2", got)
	}
}

func assertNoEvent[T any](t *testing.T, ch <-chan T, msg string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal(msg)
	default:
	}
}
