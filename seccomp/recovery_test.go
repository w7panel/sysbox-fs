package seccomp

import (
	"context"
	"fmt"
	"github.com/godbus/dbus/v5"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestListenerIdentityRoundTrip(t *testing.T) {
	want := listenerIdentity{"container:with/separators", 12, 34, 56, 78}
	name, err := want.name()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(name, ":\n") {
		t.Fatal("unsafe systemd FDNAME")
	}
	got, err := parseListenerIdentity(name)
	if err != nil || got != want {
		t.Fatalf("identity: %#v, %v", got, err)
	}
	for _, name := range []string{"stored", "seccomp.YQ.0.1.2.3", "seccomp.YQ.1.2.bad.3", "seccomp.YQ.1.2.3.4\nFDSTORE=1"} {
		if _, err := parseListenerIdentity(name); err == nil {
			t.Fatalf("accepted invalid name %q", name)
		}
	}
	if _, err := (listenerIdentity{container: strings.Repeat("x", 256)}).name(); err == nil {
		t.Fatal("accepted overlong FDNAME")
	}
}

func TestNotifyBarrierWaitsForManager(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	server, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	receive := func() (string, []int) {
		t.Helper()
		data, control := make([]byte, 1024), make([]byte, unix.CmsgSpace(4))
		n, oob, _, _, err := server.ReadMsgUnix(data, control)
		if err != nil {
			t.Fatal(err)
		}
		messages, err := unix.ParseSocketControlMessage(control[:oob])
		if err != nil {
			t.Fatal(err)
		}
		var fds []int
		for _, message := range messages {
			got, err := unix.ParseUnixRights(&message)
			if err != nil {
				t.Fatal(err)
			}
			fds = append(fds, got...)
		}
		return string(data[:n]), fds
	}
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])
	done := make(chan error, 1)
	go func() {
		err := notifyWithBarrier(path, "FDSTORE=1\nFDPOLL=0\nFDNAME=test", pipe[0])
		if err != nil {
			t.Log(err)
		}
		done <- err
	}()
	message, fds := receive()
	if message != "FDSTORE=1\nFDPOLL=0\nFDNAME=test" || len(fds) != 1 {
		t.Fatalf("store message %q, %v", message, fds)
	}
	defer unix.Close(fds[0])
	message, barrier := receive()
	if message != "BARRIER=1" || len(barrier) != 1 {
		t.Fatalf("barrier message %q, %v", message, barrier)
	}
	select {
	case err := <-done:
		t.Fatalf("returned before manager ack: %v", err)
	default:
	}
	unix.Close(barrier[0])
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type storeTestUnit struct {
	dbus.BusObject
	entries []storedFD
}

func (u *storeTestUnit) CallWithContext(_ context.Context, _ string, _ dbus.Flags, _ ...interface{}) *dbus.Call {
	entries := make([][]interface{}, 0, len(u.entries))
	for _, e := range u.entries {
		entries = append(entries, []interface{}{e.Name, e.Mode, e.DevMajor, e.DevMinor, e.Inode, e.RdevMajor, e.RdevMinor, e.Path, e.Flags})
	}
	return &dbus.Call{Body: []interface{}{entries}}
}

func TestFDStoreRequiresActualRetention(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(fmt.Sprint(retained), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "notify")
			server, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			server.SetReadDeadline(time.Now().Add(2 * time.Second))
			// The manager processes both datagrams and closes the barrier. This is
			// deliberately insufficient proof of successful storage (e.g. store full).
			done := make(chan error, 1)
			go func() {
				for i := 0; i < 2; i++ {
					data, oob := make([]byte, 1024), make([]byte, unix.CmsgSpace(4))
					_, n, _, _, err := server.ReadMsgUnix(data, oob)
					if err != nil {
						done <- err
						return
					}
					msgs, err := unix.ParseSocketControlMessage(oob[:n])
					if err != nil {
						done <- err
						return
					}
					for _, msg := range msgs {
						fds, err := unix.ParseUnixRights(&msg)
						if err != nil {
							done <- err
							return
						}
						for _, fd := range fds {
							unix.Close(fd)
						}
					}
				}
				done <- nil
			}()
			var pipe [2]int
			if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pipe[0])
			defer unix.Close(pipe[1])
			var stat unix.Stat_t
			if err := unix.Fstat(pipe[0], &stat); err != nil {
				t.Fatal(err)
			}
			unit := &storeTestUnit{}
			if retained {
				unit.entries = []storedFD{{Name: "listener", Inode: stat.Ino, DevMajor: unix.Major(uint64(stat.Dev)), DevMinor: unix.Minor(uint64(stat.Dev))}}
			}
			store := &fdStore{notify: path, unit: unit, names: make(map[int]string)}
			err = store.add(pipe[0], "listener")
			if (err == nil) != retained {
				t.Fatalf("retain=%v: %v", retained, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOwnerlessListenersRemainTrackedByContainer(t *testing.T) {
	tracer := &syscallTracer{
		service:            &SyscallMonitorService{closeSeccompOnContExit: true},
		seccompSessionCMap: make(map[string][]seccompSession),
		pidToContMap:       make(map[uint32]string),
	}
	tracer.seccompSessionAdd(seccompSession{fd: 10, cntrId: "container"})
	tracer.seccompSessionAdd(seccompSession{fd: 11, cntrId: "container"})
	if len(tracer.seccompSessionCMap["container"]) != 2 || len(tracer.pidToContMap) != 0 {
		t.Fatal("orphaned filter users lost container-level cleanup tracking")
	}
}

func TestQuiesceDrainsReceivedNotifications(t *testing.T) {
	scheduler := newNotifScheduler(1, newSeccompNotifPidTracker())
	service := &SyscallMonitorService{tracer: &syscallTracer{seccompNotifSched: scheduler}}
	release := make(chan struct{})
	started := make(chan struct{})
	scheduler.Schedule(&sysRequest{Pid: 1}, 0, "container", func(*sysRequest, int32, string) { close(started); <-release })
	<-started
	done := make(chan error, 1)
	go func() { done <- service.Quiesce() }()
	select {
	case err := <-done:
		t.Fatalf("quiesce skipped pending work: %v", err)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !service.tracer.quiescing {
		t.Fatal("quiesce did not close admission")
	}
}
