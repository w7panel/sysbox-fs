package state

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/mocks"
	"github.com/nestybox/sysbox-fs/mount"
	"github.com/nestybox/sysbox-fs/process"
	"github.com/nestybox/sysbox-fs/sysio"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sys/unix"
)

func restartFixture(t *testing.T) *RestartState {
	t.Helper()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	pid := uint32(os.Getpid())
	start, err := ProcessStartTime(pid)
	if err != nil {
		t.Fatal(err)
	}
	return &RestartState{Version: 1, BootID: strings.TrimSpace(string(boot)), Clean: true, Containers: []RestartContainer{{
		ID: "container", SharedState: "exited-original-owner", PID: pid, StartTime: start, Devices: []uint32{21},
		Ctime: time.Unix(100, 0), UID: 100000, UIDSize: 65536, GID: 100001, GIDSize: 65536,
		ProcRO: []string{"/proc/sys"}, ProcMask: []string{"/proc/kcore"},
		Data:   map[string][]byte{"/proc/sys/kernel/hostname": []byte("original")},
		Mounts: []*domain.MountInfo{{MountID: 42, MountPoint: "/proc/meminfo", MajorMinorVer: "0:21", MpInode: 43}},
	}}}
}

func TestRestartCheckpointValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if state, err := ReadRestart(path); err != nil || state != nil {
		t.Fatal("missing checkpoint", state, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*RestartState)
		valid  bool
	}{
		{"valid", func(*RestartState) {}, true},
		{"dirty", func(s *RestartState) { s.Clean = false }, false},
		{"new boot live", func(s *RestartState) { s.BootID = "other" }, false},
		{"new boot empty", func(s *RestartState) { s.BootID = "other"; s.Containers = nil }, true},
		{"version", func(s *RestartState) { s.Version++ }, false},
		{"dot id", func(s *RestartState) { s.Containers[0].ID = "." }, false},
		{"parent id", func(s *RestartState) { s.Containers[0].ID = ".." }, false},
		{"no shared state", func(s *RestartState) { s.Containers[0].SharedState = "" }, false},
		{"no devices", func(s *RestartState) { s.Containers[0].Devices = nil }, false},
		{"nil policy", func(s *RestartState) { s.Containers[0].Mounts = []*domain.MountInfo{nil} }, false},
		{"duplicate id", func(s *RestartState) { s.Containers = append(s.Containers, s.Containers[0]) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := restartFixture(t)
			test.mutate(state)
			if err := WriteRestart(path, state); err != nil {
				t.Fatal(err)
			}
			loaded, err := ReadRestart(path)
			if (err == nil) != test.valid {
				t.Fatalf("validation=%v", err)
			}
			if test.valid && !reflect.DeepEqual(state, loaded) {
				t.Fatalf("checkpoint lost fields: %+v", loaded)
			}
		})
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe checkpoint permissions")
	}
}

func restartService(t *testing.T) (*containerStateService, *mocks.FuseServerServiceIface) {
	t.Helper()
	css := NewContainerStateService().(*containerStateService)
	ioService := sysio.NewIOService(domain.IOOsFileService)
	processService := process.NewProcessService()
	processService.Setup(ioService)
	mounts := mount.NewMountService()
	mounts.Setup(css, nil, processService, nil)
	fuse := &mocks.FuseServerServiceIface{}
	css.Setup(fuse, processService, ioService, mounts)
	t.Cleanup(func() {
		for _, c := range css.idTable {
			if c.initPidFd != 0 {
				unix.Close(int(c.initPidFd))
			}
		}
	})
	return css, fuse
}

func TestRestoreSharedStateAndOriginalMountPolicy(t *testing.T) {
	state := restartFixture(t)
	sibling := state.Containers[0]
	sibling.ID = "sibling"
	state.Containers = append(state.Containers, sibling)
	css, fuse := restartService(t)
	var owners []domain.ContainerIface
	fuse.On("CreateFuseServer", mock.Anything, mock.Anything).Run(func(args mock.Arguments) { owners = append(owners, args.Get(1).(domain.ContainerIface)) }).Return(nil).Twice()
	fuse.On("FuseServerCntrRegComplete", mock.Anything).Return(nil).Twice()
	if err := RestoreRestart(css, state); err != nil {
		t.Fatal(err)
	}
	if len(owners) != 2 || owners[0] != owners[1] {
		t.Fatal("lost shared owner after original member exit")
	}
	for _, c := range css.idTable {
		if !c.IsRegistrationCompleted() || !c.Ctime().Equal(state.Containers[0].Ctime) {
			t.Fatal("lost metadata")
		}
		if !c.IsImmutableMountID(42) || c.IsImmutableMountID(999) {
			t.Fatal("lost original immutable mount policy")
		}
		if !reflect.DeepEqual(c.recoveryDevices, []uint32{21}) {
			t.Fatal("lost device allowlist")
		}
	}
	if !reflect.DeepEqual(owners[0].(*container).dataStore, state.Containers[0].Data) {
		t.Fatal("lost emulated data")
	}
	if len(css.netnsTable) != 1 {
		t.Fatal("netns sharing index not restored")
	}
	fuse.AssertExpectations(t)
}

func TestRestoreSkipsReusedPID(t *testing.T) {
	state := restartFixture(t)
	state.Containers[0].StartTime++
	css, _ := restartService(t)
	if err := RestoreRestart(css, state); err != nil {
		t.Fatal(err)
	}
	if len(css.idTable) != 0 || len(css.netnsTable) != 0 {
		t.Fatal("attached state to reused PID")
	}
}

func TestRestoreFailureRollsBackCreatedServers(t *testing.T) {
	state := restartFixture(t)
	css, fuse := restartService(t)
	fuse.On("CreateFuseServer", mock.Anything, mock.Anything).Return(nil).Once()
	fuse.On("FuseServerCntrRegComplete", mock.Anything).Return(errors.New("registration failure")).Once()
	fuse.On("DestroyFuseServer", "container").Return(nil).Once()
	if err := RestoreRestart(css, state); err == nil {
		t.Fatal("ignored restore failure")
	}
	if len(css.idTable) != 0 || len(css.netnsTable) != 0 {
		t.Fatal("partial state retained")
	}
	fuse.AssertExpectations(t)
}

func TestSaveRejectsMissingFuseSession(t *testing.T) {
	css, _ := restartService(t)
	fixture := restartFixture(t).Containers[0]
	c := newContainer(fixture.ID, fixture.PID, fixture.Ctime, 0, 65536, 0, 65536, nil, nil, css).(*container)
	c.SetRegistrationCompleted()
	css.idTable[c.id] = c
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, c.id), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "checkpoint.json")
	err := SaveRestart(css, func(string) domain.ContainerIface { return c }, path, dir, true)
	if err == nil || !strings.Contains(err.Error(), "not FUSE") {
		t.Fatal("saved host filesystem device as FUSE", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("wrote invalid checkpoint")
	}
}
