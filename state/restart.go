package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
)

// RestartState is a same-boot, graceful-restart checkpoint. It deliberately
// does not claim crash consistency with mgr or the kernel mount tree.
type RestartState struct {
	Version    int
	BootID     string
	Clean      bool
	Containers []RestartContainer
}

type RestartContainer struct {
	ResourceCacheTTL           time.Duration
	Devices                    []uint32
	Mounts                     []*domain.MountInfo
	ID                         string
	PID                        uint32
	StartTime                  uint64
	Ctime                      time.Time
	UID, UIDSize, GID, GIDSize uint32
	ProcRO, ProcMask           []string
	Identity                   domain.ResourceIdentity
	SharedState                string
	Data                       map[string][]byte
}

func ProcessStartTime(pid uint32) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, fmt.Errorf("invalid proc stat for %d", pid)
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("short proc stat for %d", pid)
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func validRestartID(id string) bool {
	return id != "" && id != "." && id != ".." && filepath.Base(id) == id
}

func ReadRestart(path string) (*RestartState, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s RestartState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	if s.Version != 1 || !s.Clean || (s.BootID != strings.TrimSpace(string(boot)) && len(s.Containers) != 0) {
		return nil, fmt.Errorf("FS checkpoint is not a clean same-boot restart; preserve mounts and recover manually")
	}
	seen := make(map[string]bool)
	for _, c := range s.Containers {
		if !validRestartID(c.ID) || !validRestartID(c.SharedState) || c.PID == 0 || c.StartTime == 0 || len(c.Devices) == 0 || c.ResourceCacheTTL < 0 || seen[c.ID] {
			return nil, fmt.Errorf("invalid FS checkpoint container %q", c.ID)
		}
		paths := make(map[string]bool)
		for _, info := range c.Mounts {
			if info == nil || info.MountID <= 0 || !filepath.IsAbs(info.MountPoint) || filepath.Clean(info.MountPoint) != info.MountPoint || paths[info.MountPoint] {
				return nil, fmt.Errorf("invalid mount policy for %s", c.ID)
			}
			paths[info.MountPoint] = true
		}
		seen[c.ID] = true
	}
	return &s, nil
}

// SaveRestart runs after registration RPCs have drained. shared returns the
// actual emulation state, including an original pod member that already exited.
func SaveRestart(service domain.ContainerStateServiceIface, shared func(string) domain.ContainerIface, path, mountpoint string, clean bool) error {
	css := service.(*containerStateService)
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	s := RestartState{Version: 1, BootID: strings.TrimSpace(string(boot)), Clean: clean}
	css.RLock()
	defer css.RUnlock()
	sharedSnapshots := make(map[*container]RestartContainer)
	for _, c := range css.idTable {
		if !c.IsRegistrationCompleted() {
			return fmt.Errorf("container %s registration is incomplete", c.id)
		}
		start, err := ProcessStartTime(c.InitPid())
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		c.intLock.RLock()
		r := RestartContainer{ID: c.id, PID: c.initPid, StartTime: start, Ctime: c.ctime,
			UID: c.uidFirst, UIDSize: c.uidSize, GID: c.gidFirst, GIDSize: c.gidSize,
			ProcRO: append([]string(nil), c.procRoPaths...), ProcMask: append([]string(nil), c.procMaskPaths...), ResourceCacheTTL: c.ResourceCacheTTL()}
		r.Devices = append([]uint32(nil), c.recoveryDevices...)
		r.Identity = c.resourceIdentity
		if c.mountInfoParser != nil {
			r.Mounts = c.mountInfoParser.(interface{ SnapshotMounts() []*domain.MountInfo }).SnapshotMounts()
		}
		c.intLock.RUnlock()
		var stat unix.Stat_t
		if err := unix.Stat(filepath.Join(mountpoint, c.id), &stat); err != nil {
			return err
		}
		var fs unix.Statfs_t
		if err := unix.Statfs(filepath.Join(mountpoint, c.id), &fs); err != nil {
			return err
		}
		if fs.Type != unix.FUSE_SUPER_MAGIC {
			return fmt.Errorf("container %s host mount is not FUSE", c.id)
		}
		device := uint32(unix.Major(uint64(stat.Dev)))<<20 | uint32(unix.Minor(uint64(stat.Dev)))
		found := false
		for _, old := range r.Devices {
			if old == device {
				found = true
			}
		}
		if !found {
			r.Devices = append(r.Devices, device)
		}
		source, ok := shared(c.id).(*container)
		if !ok {
			return fmt.Errorf("missing FUSE state for %s", c.id)
		}
		snapshot, found := sharedSnapshots[source]
		if !found {
			source.intLock.RLock()
			snapshot = RestartContainer{SharedState: source.id, Ctime: source.ctime, Data: make(map[string][]byte, len(source.dataStore))}
			for key, value := range source.dataStore {
				snapshot.Data[key] = append([]byte(nil), value...)
			}
			source.intLock.RUnlock()
			sharedSnapshots[source] = snapshot
		}
		r.SharedState, r.Ctime, r.Data = snapshot.SharedState, snapshot.Ctime, snapshot.Data
		s.Containers = append(s.Containers, r)
	}
	return WriteRestart(path, &s)
}

func WriteRestart(path string, s *RestartState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".fs-restart-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// RestoreRestart recreates fresh host FUSE sessions. Existing namespace bind
// mounts still require the reconciler; this alone does not repair containers.
func RestoreRestart(service domain.ContainerStateServiceIface, s *RestartState) (retErr error) {
	if s == nil {
		return nil
	}
	css := service.(*containerStateService)
	if len(css.idTable) != 0 {
		return fmt.Errorf("restore requires an empty container service")
	}
	var restored []*container
	servers := make(map[string]bool)
	defer func() {
		if retErr == nil {
			return
		}
		for _, c := range restored {
			if servers[c.id] {
				_ = css.fss.DestroyFuseServer(c.id)
			}
			if c.netnsInode != 0 {
				_ = css.untrackNetns(c)
			}
			delete(css.idTable, c.id)
			unix.Close(int(c.initPidFd))
		}
	}()
	shared := make(map[string]*container)
	for _, r := range s.Containers {
		start, err := ProcessStartTime(r.PID)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if start != r.StartTime {
			continue
		} // Never attach state to a reused PID.
		c := newContainer(r.ID, r.PID, r.Ctime, r.UID, r.UIDSize, r.GID, r.GIDSize, r.ProcRO, r.ProcMask, css).(*container)
		c.SetResourceIdentity(r.Identity)
		c.SetResourceCacheTTL(r.ResourceCacheTTL)
		initialized := &container{id: r.ID, service: css}
		if err := initialized.update(c); err != nil {
			return err
		}
		// update opened a pidfd; confirm it still pins the checkpoint process.
		poll := []unix.PollFd{{Fd: int32(initialized.initPidFd), Events: unix.POLLIN}}
		exited, pollErr := unix.Poll(poll, 0)
		current, startErr := ProcessStartTime(r.PID)
		if pollErr != nil || (startErr != nil && !os.IsNotExist(startErr)) {
			unix.Close(int(initialized.initPidFd))
			if pollErr != nil {
				return pollErr
			}
			return startErr
		}
		if exited != 0 || startErr != nil || current != r.StartTime {
			unix.Close(int(initialized.initPidFd))
			continue
		}
		c = initialized
		restored = append(restored, c)
		c.recoveryDevices = append([]uint32(nil), r.Devices...)
		if r.Mounts != nil {
			parser, err := css.mts.NewMountInfoParser(c, c.initProc, false, true, false)
			if err != nil {
				return err
			}
			parser.(interface{ RestoreMounts([]*domain.MountInfo) }).RestoreMounts(r.Mounts)
			c.mountInfoParser = parser
		}
		state := shared[r.SharedState]
		if state == nil {
			state = c
			state.dataStore = r.Data
			shared[r.SharedState] = state
		}
		css.idTable[r.ID] = c
		if _, err := css.trackNetns(c, ""); err != nil {
			return err
		}
		if err := css.fss.CreateFuseServer(c, state); err != nil {
			return err
		}
		servers[c.id] = true
		if err := css.fss.FuseServerCntrRegComplete(c); err != nil {
			return err
		}
		c.SetRegistrationCompleted()
	}
	return nil
}

// RefreshRecoveredMounts retains the initial immutable policy while updating
// the IDs/inodes of replaced FUSE mounts. The caller serializes repairs per ns.
func RefreshRecoveredMounts(service domain.ContainerStateServiceIface, id string, paths []string) error {
	c, ok := service.ContainerLookupById(id).(*container)
	if !ok {
		return fmt.Errorf("unknown recovered container %s", id)
	}
	current, err := service.MountService().NewMountInfoParser(c, c.InitProc(), true, true, true)
	if err != nil {
		return err
	}
	c.intLock.Lock()
	defer c.intLock.Unlock()
	if c.mountInfoParser == nil {
		return nil
	}
	c.mountInfoParser.(interface {
		RefreshRecoveredMounts([]string, domain.MountInfoParserIface)
	}).RefreshRecoveredMounts(paths, current)
	return nil
}
