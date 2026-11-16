package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nestybox/sysbox-fs/recovery"
	"github.com/nestybox/sysbox-fs/state"
	"golang.org/x/sys/unix"
)

func TestRecoveryUsesInitAfterReaderExits(t *testing.T) {
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/mnt", &ns); err != nil {
		t.Fatal(err)
	}
	got, err := recoveryPID(context.Background(), recovery.Fault{PID: ^uint32(0), Namespace: ns.Ino}, state.RestartContainer{PID: uint32(os.Getpid())})
	if err != nil || got != uint32(os.Getpid()) {
		t.Fatalf("pid=%d err=%v", got, err)
	}
}

func TestNamespaceSearchStaysInContainerCgroup(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	child := filepath.Join(root, "nested")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/mnt", &ns); err != nil {
		t.Fatal(err)
	}
	data := []byte(fmt.Sprintf("%d\n", os.Getpid()))
	if err := os.WriteFile(filepath.Join(outside, "cgroup.procs"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	if _, err := findNamespaceProcess(context.Background(), root, ns.Ino); err == nil {
		t.Fatal("followed cgroup symlink outside registered subtree")
	}
	younger := exec.Command("sleep", "10")
	if err := younger.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { younger.Process.Kill(); younger.Wait() }()
	data = []byte(fmt.Sprintf("%d\n%d\n", younger.Process.Pid, os.Getpid()))
	if err := os.WriteFile(filepath.Join(child, "cgroup.procs"), data, 0600); err != nil {
		t.Fatal(err)
	}
	pid, err := findNamespaceProcess(context.Background(), root, ns.Ino)
	if err != nil || pid != uint32(os.Getpid()) {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := findNamespaceProcess(ctx, root, ns.Ino); err != context.Canceled {
		t.Fatalf("cancel error: %v", err)
	}
}
