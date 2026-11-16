package recovery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

const MountHelperArg = "--recover-mount-helper"
const StaleTargetExitCode = 3

var ErrUnsupportedPropagation = errors.New("unsupported mount propagation")

type Device struct{ Major, Minor uint32 }

type mountReplacement struct {
	device      Device
	ID          int
	Target      string
	Root        string
	Attributes  uint64
	Propagation uint64
	SourceFD    int
	Children    []mountReplacement
	TargetFD    int
}

type namespaceLock struct {
	sync.Mutex
	users int
}

var namespaceLocks = struct {
	sync.Mutex
	locks map[uint64]*namespaceLock
}{locks: make(map[uint64]*namespaceLock)}

var mountHelpers sync.Map

func IsMountHelperPID(pid uint32) bool {
	_, ok := mountHelpers.Load(pid)
	return ok
}

func lockNamespace(inode uint64) func() {
	namespaceLocks.Lock()
	lock := namespaceLocks.locks[inode]
	if lock == nil {
		lock = &namespaceLock{}
		namespaceLocks.locks[inode] = lock
	}
	lock.users++
	namespaceLocks.Unlock()
	lock.Lock()
	return func() {
		lock.Unlock()
		namespaceLocks.Lock()
		defer namespaceLocks.Unlock()
		lock.users--
		if lock.users == 0 {
			delete(namespaceLocks.locks, inode)
		}
	}
}

func mountPlan(reader io.Reader, allowed []Device) ([]mountReplacement, error) {
	mounts, err := mountinfo.GetMountsFromReader(reader, nil)
	if err != nil {
		return nil, err
	}
	devices := make(map[Device]bool, len(allowed))
	for _, dev := range allowed {
		devices[dev] = true
	}
	var plan []mountReplacement
	for _, mount := range mounts {
		if mount.FSType != "fuse" || mount.Source != "sysboxfs" || !devices[Device{uint32(mount.Major), uint32(mount.Minor)}] {
			continue
		}
		if !filepath.IsAbs(mount.Root) || filepath.Clean(mount.Root) != mount.Root || !filepath.IsAbs(mount.Mountpoint) || filepath.Clean(mount.Mountpoint) != mount.Mountpoint {
			return nil, fmt.Errorf("invalid FUSE mount path")
		}
		item := mountReplacement{device: Device{uint32(mount.Major), uint32(mount.Minor)}, ID: mount.ID, Target: mount.Mountpoint, Root: mount.Root, Propagation: unix.MS_PRIVATE}
		for _, option := range strings.Fields(mount.Optional) {
			if option == "unbindable" {
				item.Propagation = unix.MS_UNBINDABLE
				continue
			}
			// A new FUSE superblock cannot join the old mount's propagation group.
			if strings.HasPrefix(option, "shared:") || strings.HasPrefix(option, "master:") || strings.HasPrefix(option, "propagate_from:") {
				return nil, fmt.Errorf("%w: mount %s has %s", ErrUnsupportedPropagation, item.Target, option)
			}
		}
		for _, option := range strings.Split(mount.Options, ",") {
			switch option {
			case "ro":
				item.Attributes |= unix.MOUNT_ATTR_RDONLY
			case "nosuid":
				item.Attributes |= unix.MOUNT_ATTR_NOSUID
			case "nodev":
				item.Attributes |= unix.MOUNT_ATTR_NODEV
			case "noexec":
				item.Attributes |= unix.MOUNT_ATTR_NOEXEC
			case "noatime":
				item.Attributes |= unix.MOUNT_ATTR_NOATIME
			case "strictatime":
				item.Attributes |= unix.MOUNT_ATTR_STRICTATIME
			case "nodiratime":
				item.Attributes |= unix.MOUNT_ATTR_NODIRATIME
			case "nosymfollow":
				item.Attributes |= unix.MOUNT_ATTR_NOSYMFOLLOW
			}
		}
		plan = append(plan, item)
	}
	visible := plan[:0]
	for _, item := range plan {
		covered := false
		for _, m := range mounts {
			if m.Parent == item.ID && m.Mountpoint == item.Target {
				covered = true
				break
			}
		}
		if !covered {
			visible = append(visible, item)
		}
	}
	plan = visible
	// Keep complete child subtrees when replacing their FUSE parent.
	for i := range plan {
		parent := &plan[i]
		for _, child := range mounts {
			if child.Parent != parent.ID {
				continue
			}
			subtree := mountReplacement{ID: child.ID, Target: child.Mountpoint}
			ids := map[int]bool{child.ID: true}
			for changed := true; changed; {
				changed = false
				for _, m := range mounts {
					if ids[m.Parent] && !ids[m.ID] {
						ids[m.ID] = true
						changed = true
					}
				}
			}
			for _, m := range mounts {
				if !ids[m.ID] {
					continue
				}
				if !strings.HasPrefix(m.Mountpoint, parent.Target+"/") {
					return nil, fmt.Errorf("invalid child mount path %s", m.Mountpoint)
				}
				if strings.Contains(m.Optional, "shared:") || strings.Contains(m.Optional, "master:") || strings.Contains(m.Optional, "propagate_from:") || strings.Contains(m.Optional, "unbindable") {
					return nil, fmt.Errorf("%w: child mount %s", ErrUnsupportedPropagation, m.Mountpoint)
				}
				if m.FSType == "fuse" && m.Source == "sysboxfs" && devices[Device{uint32(m.Major), uint32(m.Minor)}] {
					return nil, fmt.Errorf("nested disconnected FUSE child: %s", m.Mountpoint)
				}
				if m.ID != child.ID {
					subtree.Children = append(subtree.Children, mountReplacement{ID: m.ID, Target: m.Mountpoint})
				}
			}
			parent.Children = append(parent.Children, subtree)
		}
	}
	return plan, nil
}

func openRootPath(rootfd int, path string) (int, error) {
	return unix.Openat2(rootfd, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
}

// mountID reads only proc metadata: fstat on a dead FUSE inode may itself fail.
func mountID(fd int) (int, error) {
	return mountIDAt(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fdinfo/%d", fd))
}

func mountIDAt(dirfd int, path string) (int, error) {
	fd, err := unix.Openat(dirfd, path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) == 2 && fields[0] == "mnt_id:" {
			return strconv.Atoi(fields[1])
		}
	}
	if err := scan.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("fdinfo %s has no mount ID", path)
}

func processAlive(pidfd int) error {
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("target process exited: %w", unix.ESRCH)
	}
	return nil
}

// RepairMounts replaces only explicitly allowed, dead sysboxfs devices. Paths
// are resolved from pinned roots; only mount FDs cross into the helper process.
// Success does not repair already-open file descriptors on the old connection.
func RepairMounts(ctx context.Context, pid int, base, containerID string, allowed []Device) ([]string, error) {
	if pid <= 0 || containerID == "" || containerID == "." || containerID == ".." || filepath.Base(containerID) != containerID {
		return nil, fmt.Errorf("invalid recovery target")
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pidfd)
	nsfd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(nsfd)
	var ns unix.Stat_t
	if err := unix.Fstat(nsfd, &ns); err != nil {
		return nil, err
	}
	unlock := lockNamespace(ns.Ino)
	defer unlock()
	rootfd, err := unix.Open(fmt.Sprintf("/proc/%d/root", pid), unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootfd)
	info, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return nil, err
	}
	plan, err := mountPlan(info, allowed)
	info.Close()
	if err != nil {
		return nil, err
	}
	if err := processAlive(pidfd); err != nil {
		return nil, err
	}
	if len(plan) == 0 {
		return nil, nil
	}
	sourceRoot, err := unix.Open(filepath.Join(base, containerID), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(sourceRoot)
	// ExtraFiles are duped here so their cleanup has no overlap with the pinned
	// descriptors owned by this function.
	var files []*os.File
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	addFile := func(fd int) (int, error) {
		copy, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return 0, err
		}
		files = append(files, os.NewFile(uintptr(copy), "recovery"))
		return len(files) + 2, nil
	}
	for _, fd := range []int{nsfd, rootfd, pidfd} {
		if _, err := addFile(fd); err != nil {
			return nil, err
		}
	}
	var ready []mountReplacement
	for i := range plan {
		item := &plan[i]
		target, err := openRootPath(rootfd, item.Target)
		if err != nil {
			return nil, fmt.Errorf("open target %s: %w", item.Target, err)
		}
		id, err := mountID(target)
		if err != nil {
			unix.Close(target)
			return nil, err
		}
		// mountinfo also lists covered old mounts after a successful repair.
		if id != item.ID {
			unix.Close(target)
			continue
		}
		// The target FD pins the superblock before we check device reuse.
		// A historical device number may now belong to another live session.
		live, err := liveDevice(base, item.device)
		if err != nil {
			unix.Close(target)
			return nil, err
		}
		if live {
			unix.Close(target)
			continue
		}
		item.TargetFD, err = addFile(target)
		unix.Close(target)
		if err != nil {
			return nil, err
		}
		source, err := openRootPath(sourceRoot, item.Root)
		if err != nil {
			return nil, fmt.Errorf("open replacement %s: %w", item.Root, err)
		}
		var stat unix.Statfs_t
		err = unix.Fstatfs(source, &stat)
		if err != nil || stat.Type != unix.FUSE_SUPER_MAGIC {
			unix.Close(source)
			return nil, fmt.Errorf("replacement is not FUSE: %s: %v", item.Root, err)
		}
		clone, err := unix.OpenTree(source, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
		unix.Close(source)
		if err != nil {
			return nil, fmt.Errorf("clone replacement %s: %w", item.Target, err)
		}
		const attributes = unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC | unix.MOUNT_ATTR__ATIME | unix.MOUNT_ATTR_NODIRATIME | unix.MOUNT_ATTR_NOSYMFOLLOW
		err = unix.MountSetattr(clone, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: item.Attributes, Attr_clr: attributes&^item.Attributes | unix.MOUNT_ATTR__ATIME, Propagation: item.Propagation})
		if err != nil {
			unix.Close(clone)
			return nil, fmt.Errorf("set replacement attributes %s: %w", item.Target, err)
		}
		for j := range item.Children {
			child := &item.Children[j]
			childFD, err := openRootPath(rootfd, child.Target)
			if err != nil {
				unix.Close(clone)
				return nil, err
			}
			childID, err := mountID(childFD)
			if err != nil || childID != child.ID {
				unix.Close(childFD)
				unix.Close(clone)
				return nil, fmt.Errorf("child mount changed: %s", child.Target)
			}
			child.SourceFD, err = addFile(childFD)
			unix.Close(childFD)
			if err != nil {
				unix.Close(clone)
				return nil, err
			}
		}
		item.SourceFD, err = addFile(clone)
		unix.Close(clone)
		if err != nil {
			return nil, err
		}
		ready = append(ready, *item)
	}
	if len(ready) == 0 {
		return nil, nil
	}
	data, err := json.Marshal(ready)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe, MountHelperArg)
	cmd.ExtraFiles = files
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	defer stdin.Close()
	var output, diagnostics bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &diagnostics
	err = cmd.Start()
	if err == nil {
		pid := uint32(cmd.Process.Pid)
		mountHelpers.Store(pid, struct{}{})
		_, writeErr := stdin.Write(data)
		stdin.Close()
		err = cmd.Wait()
		mountHelpers.Delete(pid)
		if err == nil {
			err = writeErr
		}
	}
	var completed []string
	decodeErr := json.Unmarshal(output.Bytes(), &completed)
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == StaleTargetExitCode {
			return completed, fmt.Errorf("mount recovery helper: %w", unix.ESRCH)
		}
		return completed, fmt.Errorf("mount recovery helper: %w: %s", err, diagnostics.String())
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("mount recovery helper result: %w", decodeErr)
	}
	return completed, nil
}

// RunMountHelper must run in a dedicated re-exec process which exits directly
// afterwards. The caller must not resume the daemon on this namespace thread.
func RunMountHelper() error {
	var completed []string
	defer func() { _ = json.NewEncoder(os.Stdout).Encode(completed) }()
	var plan []mountReplacement
	if err := json.NewDecoder(os.Stdin).Decode(&plan); err != nil {
		return err
	}
	runtime.LockOSThread()
	if err := processAlive(5); err != nil {
		return err
	}
	fdinfo, err := unix.Open("/proc/self/fdinfo", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fdinfo)
	helperMountID := func(fd int) (int, error) {
		return mountIDAt(fdinfo, strconv.Itoa(fd))
	}
	hostNS, err := unix.Open("/proc/self/ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(hostNS)
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return err
	}
	if err := unix.Setns(3, unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("enter child source namespace: %w", err)
	}
	// open_tree requires its source mount to belong to the calling namespace.
	for i := range plan {
		for j := range plan[i].Children {
			child := &plan[i].Children[j]
			fd, err := unix.OpenTree(child.SourceFD, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH|unix.AT_RECURSIVE)
			if err != nil {
				return fmt.Errorf("clone child %s: %w", child.Target, err)
			}
			child.SourceFD = fd
		}
	}
	if err := unix.Setns(hostNS, unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("return to host namespace: %w", err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("create staging namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make staging mounts private: %w", err)
	}
	for i := range plan {
		if len(plan[i].Children) == 0 {
			continue
		}
		if err := stageMountTree(&plan[i]); err != nil {
			return err
		}
	}
	if err := unix.Setns(3, unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("enter target mount namespace: %w", err)
	}
	for _, item := range plan {
		pinned, err := helperMountID(item.TargetFD)
		if err != nil || pinned != item.ID {
			return fmt.Errorf("pinned target mount changed: %s", item.Target)
		}
		target, err := openRootPath(4, item.Target)
		if err != nil {
			return fmt.Errorf("open target %s in mount namespace: %w", item.Target, err)
		}
		current, err := helperMountID(target)
		if err != nil || current != item.ID {
			unix.Close(target)
			return fmt.Errorf("target mount changed: %s", item.Target)
		}
		for _, child := range item.Children {
			for _, preserved := range append([]mountReplacement{child}, child.Children...) {
				fd, err := openRootPath(4, preserved.Target)
				if err != nil {
					unix.Close(target)
					return fmt.Errorf("open child %s in mount namespace: %w", preserved.Target, err)
				}
				id, err := helperMountID(fd)
				unix.Close(fd)
				if err != nil || id != preserved.ID {
					unix.Close(target)
					return fmt.Errorf("child mount changed: %s", preserved.Target)
				}
			}
		}
		if err := processAlive(5); err != nil {
			unix.Close(target)
			return err
		}
		err = unix.MoveMount(item.SourceFD, "", target, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH)
		unix.Close(target)
		if err != nil {
			return fmt.Errorf("replace %s: %w", item.Target, err)
		}
		completed = append(completed, item.Target)
		for _, child := range item.Children {
			completed = append(completed, child.Target)
			for _, descendant := range child.Children {
				completed = append(completed, descendant.Target)
			}
		}
	}
	return nil
}

func liveDevice(base string, device Device) (bool, error) {
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return false, err
	}
	return deviceInHostTree(mounts, base, device), nil
}
func deviceInHostTree(mounts []*mountinfo.Info, base string, device Device) bool {
	for _, m := range mounts {
		if m.FSType == "fuse" && m.Source == "sysboxfs" && uint32(m.Major) == device.Major && uint32(m.Minor) == device.Minor && (m.Mountpoint == base || strings.HasPrefix(m.Mountpoint, filepath.Clean(base)+"/")) {
			return true
		}
	}
	return false
}

// move_mount requires an attached destination. Assemble child mounts in this
// helper's private namespace, then clone the whole tree for atomic replacement.
func stageMountTree(item *mountReplacement) error {
	dir, err := os.MkdirTemp("", "sysbox-recovery-")
	if err != nil {
		return err
	}
	defer os.Remove(dir)
	if err := unix.MoveMount(item.SourceFD, "", unix.AT_FDCWD, dir, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("stage parent %s: %w", item.Target, err)
	}
	defer unix.Unmount(dir, unix.MNT_DETACH)
	for _, child := range item.Children {
		target, err := openRootPath(item.SourceFD, strings.TrimPrefix(child.Target, item.Target))
		if err != nil {
			return fmt.Errorf("open staged child target %s: %w", child.Target, err)
		}
		err = unix.MoveMount(child.SourceFD, "", target, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH)
		unix.Close(target)
		if err != nil {
			return fmt.Errorf("stage child %s: %w", child.Target, err)
		}
	}
	fd, err := unix.OpenTree(item.SourceFD, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH|unix.AT_RECURSIVE)
	if err != nil {
		return fmt.Errorf("clone staged tree %s: %w", item.Target, err)
	}
	item.SourceFD = fd
	return nil
}
