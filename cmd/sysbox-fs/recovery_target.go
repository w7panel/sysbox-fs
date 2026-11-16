package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nestybox/sysbox-fs/recovery"
	"github.com/nestybox/sysbox-fs/state"
	"github.com/nestybox/sysbox-runc/libcontainer/cgroups"
	"golang.org/x/sys/unix"
)

func inMountNamespace(pid uint32, namespace uint64) bool {
	var stat unix.Stat_t
	return unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &stat) == nil && stat.Ino == namespace
}

// A failing cat often exits before its BPF event is consumed. Prefer the
// registered init, then search only that container's cgroup for a live peer.
func recoveryPID(ctx context.Context, fault recovery.Fault, container state.RestartContainer) (uint32, error) {
	if inMountNamespace(container.PID, fault.Namespace) {
		return container.PID, nil
	}
	if inMountNamespace(fault.PID, fault.Namespace) {
		return fault.PID, nil
	}
	paths, err := cgroups.ParseCgroupFile(fmt.Sprintf("/proc/%d/cgroup", container.PID))
	if err != nil {
		return 0, err
	}
	path, base := paths[""], "/sys/fs/cgroup"
	if path == "" {
		path = paths["pids"]
		var root string
		base, root, err = cgroups.FindCgroupMountpointAndRoot("", "pids")
		if err != nil {
			return 0, err
		}
		path, err = filepath.Rel(root, path)
		if err != nil || path == ".." || strings.HasPrefix(path, "../") {
			return 0, fmt.Errorf("container cgroup is outside its mount")
		}
	}
	path = strings.TrimSuffix(filepath.Clean(path), "/init.scope")
	if path == "" || path == "/" || path == "." {
		return 0, fmt.Errorf("refusing to search host cgroup root")
	}
	return findNamespaceProcess(ctx, filepath.Join(base, path), fault.Namespace)
}

func findNamespaceProcess(ctx context.Context, root string, namespace uint64) (uint32, error) {
	var found uint32
	var oldest uint64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, value := range strings.Fields(string(data)) {
			pid, err := strconv.ParseUint(value, 10, 32)
			if err != nil || !inMountNamespace(uint32(pid), namespace) {
				continue
			}
			start, err := state.ProcessStartTime(uint32(pid))
			if err == nil && (found == 0 || start < oldest) {
				found = uint32(pid)
				oldest = start
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if found == 0 {
		return 0, fmt.Errorf("no live process in mount namespace %d", namespace)
	}
	return found, nil
}
