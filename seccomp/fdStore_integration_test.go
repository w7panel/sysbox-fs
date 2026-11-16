package seccomp

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	unixIpc "github.com/nestybox/sysbox-ipc/unix"
	"github.com/nestybox/sysbox-runc/libcontainer/system"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// Opt-in: run the compiled test binary as an isolated systemd service with
// KillMode=process, Restart=on-failure, FDStoreMax>0 and FDStorePreserve=yes.
// The first invocation exits after a real seccomp request is pending. The
// restarted process must receive the stored listener and answer that request.
func TestSystemdFDStoreRestart(t *testing.T) {
	dir := os.Getenv("SYSBOX_FDSTORE_TEST_DIR")
	if dir == "" {
		t.Skip("requires isolated systemd service")
	}
	store, err := newFDStore()
	if err != nil {
		t.Fatal(err)
	}
	phase := filepath.Join(dir, "pending")
	if _, err := os.Stat(phase); os.IsNotExist(err) {
		socket := filepath.Join(dir, "tracee.sock")
		server, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		server.SetDeadline(time.Now().Add(10 * time.Second))
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		worker := exec.Command(binary, "-test.run=^TestSystemdFDStoreTracee$", "-test.v")
		worker.Stdout, worker.Stderr = os.Stdout, os.Stderr
		if err := worker.Start(); err != nil {
			t.Fatal(err)
		}
		conn, err := server.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		pid, _, fd, err := unixIpc.RecvSeccompInitMsg(conn)
		if err != nil {
			t.Fatal(err)
		}
		stat, err := system.Stat(int(pid))
		if err != nil {
			t.Fatal(err)
		}
		name, err := (listenerIdentity{"probe", uint32(pid), stat.StartTime, uint32(pid), stat.StartTime}).name()
		if err != nil {
			t.Fatal(err)
		}
		if err := store.add(int(fd), name); err != nil {
			t.Fatal(err)
		}
		if err := unixIpc.SendSeccompInitAckMsg(conn); err != nil {
			t.Fatal(err)
		}
		poll := []unix.PollFd{{Fd: fd, Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, 10000); err != nil || poll[0].Revents&unix.POLLIN == 0 {
			t.Fatalf("no pending seccomp request: %v %v", poll, err)
		}
		if err := os.WriteFile(phase, []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		fmt.Println("listener retained; restarting service with syscall pending")
		os.Exit(23)
	}
	if os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_PID") != fmt.Sprint(os.Getpid()) {
		t.Fatal("systemd did not restore one listener")
	}
	const fd = 3
	name, err := os.ReadFile(phase)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("LISTEN_FDNAMES") != string(name) {
		t.Fatal("listener name changed")
	}
	store.names[fd] = string(name)
	request, err := libseccomp.NotifReceive(fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := libseccomp.NotifRespond(fd, &libseccomp.ScmpNotifResp{ID: request.ID, Val: 424242}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		result, err := os.ReadFile(filepath.Join(dir, "result"))
		if err == nil {
			if string(result) != "424242" {
				t.Fatalf("tracee result %s", result)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tracee did not resume after listener recovery")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := store.remove(fd); err != nil {
		t.Fatal(err)
	}
	entries, err := store.entries()
	if err != nil || len(entries) != 0 {
		t.Fatalf("store not empty after cleanup: %v %v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "passed"), []byte("pending seccomp request survived service restart; store cleaned\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSystemdFDStoreTracee(t *testing.T) {
	dir := os.Getenv("SYSBOX_FDSTORE_TEST_DIR")
	if dir == "" {
		t.Skip("requires isolated systemd service")
	}
	runtime.LockOSThread()
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		t.Fatal(err)
	}
	call, err := libseccomp.GetSyscallFromName("getppid")
	if err != nil {
		t.Fatal(err)
	}
	if err := filter.AddRule(call, libseccomp.ActNotify); err != nil {
		t.Fatal(err)
	}
	if err := filter.Load(); err != nil {
		t.Fatal(err)
	}
	fd, err := filter.GetNotifFd()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := unixIpc.Connect(filepath.Join(dir, "tracee.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := unixIpc.SendSeccompInitMsg(conn, int32(os.Getpid()), "probe", int32(fd)); err != nil {
		t.Fatal(err)
	}
	if err := unixIpc.RecvSeccompInitAckMsg(conn); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	// Only the monitor and systemd may hold the listener during replacement.
	unix.Close(int(fd))
	value, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if err := os.WriteFile(filepath.Join(dir, "result"), []byte(fmt.Sprint(value)), 0600); err != nil {
		t.Fatal(err)
	}
}
