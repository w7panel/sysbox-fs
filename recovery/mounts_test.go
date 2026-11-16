package recovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == MountHelperArg {
		if err := RunMountHelper(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestMountPlanWhitelistAndAttributes(t *testing.T) {
	input := `10 1 0:21 /proc/meminfo /proc/meminfo ro,nosuid,nodev,noexec,relatime - fuse sysboxfs rw
11 1 0:22 / /unrelated rw - fuse sysboxfs rw
12 1 0:21 / /wrong-source rw - fuse other rw
13 1 0:21 / /wrong-type rw - ext4 sysboxfs rw
`
	plan, err := mountPlan(strings.NewReader(input), []Device{{0, 21}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].ID != 10 || plan[0].Attributes != unix.MOUNT_ATTR_RDONLY|unix.MOUNT_ATTR_NOSUID|unix.MOUNT_ATTR_NODEV|unix.MOUNT_ATTR_NOEXEC || plan[0].Propagation != unix.MS_PRIVATE {
		t.Fatalf("wrong plan: %+v", plan)
	}
	for _, option := range []string{"shared:2", "master:3", "propagate_from:4"} {
		line := strings.Replace(strings.Split(input, "\n")[0], " - ", " "+option+" - ", 1)
		if _, err := mountPlan(strings.NewReader(line), []Device{{0, 21}}); err == nil {
			t.Fatal("accepted unsupported propagation", option)
		}
	}
	nested := input + "14 10 0:33 / /proc/meminfo/child rw - tmpfs tmpfs rw\n"
	if plan, err := mountPlan(strings.NewReader(nested), []Device{{0, 21}}); err != nil || len(plan[0].Children) != 1 {
		t.Fatalf("child mount not preserved: %v %v", plan, err)
	}
}

func TestPinnedRootRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("/etc", filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if opened, err := openRootPath(fd, "/escape/passwd"); err == nil {
		unix.Close(opened)
		t.Fatal("followed symlink")
	}
}

type recoveryFS struct{ value string }

func (f recoveryFS) Root() (fs.Node, error) { return recoveryDir{f.value}, nil }

type recoveryDir struct{ value string }

func (d recoveryDir) Attr(_ context.Context, a *fuse.Attr) error {
	a.Mode = os.ModeDir | 0755
	return nil
}
func (d recoveryDir) Lookup(_ context.Context, name string) (fs.Node, error) {
	if name == "masked" {
		return recoveryDir{d.value + "/masked"}, nil
	}
	if name != "value" {
		return nil, syscall.ENOENT
	}
	return recoveryFile{d.value}, nil
}

type recoveryFile struct{ value string }

func (f recoveryFile) Attr(_ context.Context, a *fuse.Attr) error {
	a.Mode = 0444
	a.Size = uint64(len(f.value))
	return nil
}
func (f recoveryFile) ReadAll(context.Context) ([]byte, error) { return []byte(f.value), nil }

// The real FUSE mounts exist only in this test's dedicated child mount namespace.
func TestMountRecoveryPrivileged(t *testing.T) {
	if os.Getenv("SYSBOX_RECOVERY_TEST_CHILD") == "" {
		if os.Getenv("SYSBOX_RECOVERY_PRIVILEGED") != "1" {
			t.Skip("set SYSBOX_RECOVERY_PRIVILEGED=1 for isolated namespace FUSE test")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestMountRecoveryPrivileged$", "-test.v", "-test.timeout=15s")
		cmd.Env = append(os.Environ(), "SYSBOX_RECOVERY_TEST_CHILD=1", "SYSBOX_RECOVERY_TEST_DIR="+t.TempDir())
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("namespace test: %v\n%s", err, output)
		} else {
			t.Log(string(output))
		}
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	dir := os.Getenv("SYSBOX_RECOVERY_TEST_DIR")
	oldPath, newPath := filepath.Join(dir, "old"), filepath.Join(dir, "new", "container")
	for _, path := range []string{oldPath, newPath} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	control := filepath.Join(dir, "fusectl")
	if err := os.Mkdir(control, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("fusectl", control, "fusectl", 0, ""); err != nil {
		t.Fatal(err)
	}
	mountFS := func(path, value string) *fuse.Conn {
		conn, err := fuse.Mount(path, fuse.FSName("sysboxfs"))
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = fs.Serve(conn, recoveryFS{value}) }()
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = os.WriteFile(filepath.Join(control, fmt.Sprint(unix.Minor(st.Dev)), "abort"), []byte("1"), 0200)
			_ = conn.Close()
		})
		return conn
	}
	old := mountFS(oldPath, "old")
	mountFS(newPath, "new")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(filepath.Join(oldPath, "value"), target, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(oldPath, tree, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(tree, "masked")
	if err := unix.Mount("tmpfs", child, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4096"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "retained"), []byte("private-child"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", child, "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(target, &stat); err != nil {
		t.Fatal(err)
	}
	allowed := []Device{{uint32(unix.Major(stat.Dev)), uint32(unix.Minor(stat.Dev))}}
	oldFD, err := unix.Open(target, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	events, err := NewEvents([]uint32{allowed[0].Major<<20 | allowed[0].Minor})
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	faults := make(chan Fault, 16)
	go func() {
		for {
			fault, err := events.Read()
			if err != nil {
				return
			}
			faults <- fault
		}
	}()
	// Abort only this test's FUSE connection; the private fusectl mount avoids
	// changing the host mount table and wakes bazil's blocked device reader.
	if err := os.WriteFile(filepath.Join(control, fmt.Sprint(allowed[0].Minor), "abort"), []byte("1"), 0200); err != nil {
		t.Fatal(err)
	}
	old.Close()
	defer unix.Close(oldFD)
	if _, err := os.ReadFile(target); err == nil {
		t.Fatal("disconnected mount unexpectedly readable")
	}
	select {
	case fault := <-faults:
		var ns unix.Stat_t
		if err := unix.Stat("/proc/self/ns/mnt", &ns); err != nil {
			t.Fatal(err)
		}
		if fault.Device != allowed[0].Major<<20|allowed[0].Minor || fault.Namespace != ns.Ino {
			t.Fatalf("incorrect fault identity: %+v", fault)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no eBPF event for disconnected FUSE open")
	}
	for i := 0; i < 50; i++ {
		_, _ = os.ReadFile(target)
	}
	select {
	case fault := <-faults:
		t.Fatalf("cooldown did not suppress %+v", fault)
	case <-time.After(100 * time.Millisecond):
	}
	time.Sleep(time.Second)
	_, _ = os.ReadFile(target)
	select {
	case <-faults:
	case <-time.After(2 * time.Second):
		t.Fatal("no event after cooldown")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resultPath := filepath.Join(dir, "repair-result")
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMountRecoveryForeignNamespace$", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), "SYSBOX_RECOVERY_FOREIGN_PID="+strconv.Itoa(os.Getpid()), "SYSBOX_RECOVERY_FOREIGN_DEVICE="+strconv.Itoa(int(allowed[0].Minor)), "SYSBOX_RECOVERY_FOREIGN_BASE="+filepath.Join(dir, "new"), "SYSBOX_RECOVERY_FOREIGN_RESULT="+resultPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("foreign namespace repair: %v: %s", err, output)
	}
	result, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	var completed []string
	err = json.Unmarshal(result, &completed)
	if err != nil {
		t.Fatal(err)
	}
	foundChild := false
	for _, path := range completed {
		if path == child {
			foundChild = true
		}
	}
	if !foundChild {
		t.Fatal("preserved child missing from mount-policy refresh paths")
	}
	retained, err := os.ReadFile(filepath.Join(child, "retained"))
	if err != nil || string(retained) != "private-child" {
		t.Fatalf("lost masked child: %q %v", retained, err)
	}
	var childFlags unix.Statfs_t
	if err := unix.Statfs(child, &childFlags); err != nil || childFlags.Flags&unix.ST_RDONLY == 0 {
		t.Fatalf("child attributes lost: %v %v", childFlags, err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "new" {
		t.Fatalf("recovered open: %q %v", data, err)
	}
	if _, err := unix.Read(oldFD, make([]byte, 16)); err == nil {
		t.Fatal("old descriptor unexpectedly repaired")
	}
	var flags unix.Statfs_t
	if err := unix.Statfs(target, &flags); err != nil {
		t.Fatal(err)
	}
	expected := int64(unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	if flags.Flags&expected != expected {
		t.Fatalf("lost mount attributes: %x", flags.Flags)
	}
	if _, err := RepairMounts(ctx, os.Getpid(), filepath.Join(dir, "new"), "container", allowed); err != nil {
		t.Fatal("retry not idempotent", err)
	}
}

func TestReusedDeviceBelongingToLiveHostSession(t *testing.T) {
	mounts, err := mountinfo.GetMountsFromReader(strings.NewReader("11 1 0:22 / /var/lib/sysboxfs/other rw - fuse sysboxfs rw\n12 1 0:23 / /outside rw - fuse sysboxfs rw\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !deviceInHostTree(mounts, "/var/lib/sysboxfs", Device{0, 22}) {
		t.Fatal("live reused device accepted")
	}
	if deviceInHostTree(mounts, "/var/lib/sysboxfs", Device{0, 23}) {
		t.Fatal("unrelated tree rejected")
	}
	if deviceInHostTree(mounts, "/var/lib/sysbox", Device{0, 22}) {
		t.Fatal("path prefix boundary ignored")
	}
}

func TestMountRecoveryForeignNamespace(t *testing.T) {
	pid, err := strconv.Atoi(os.Getenv("SYSBOX_RECOVERY_FOREIGN_PID"))
	if err != nil {
		t.Skip("invoked only by privileged recovery test")
	}
	minor, err := strconv.Atoi(os.Getenv("SYSBOX_RECOVERY_FOREIGN_DEVICE"))
	if err != nil {
		t.Fatal(err)
	}
	paths, err := RepairMounts(context.Background(), pid, os.Getenv("SYSBOX_RECOVERY_FOREIGN_BASE"), "container", []Device{{0, uint32(minor)}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("SYSBOX_RECOVERY_FOREIGN_RESULT"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
