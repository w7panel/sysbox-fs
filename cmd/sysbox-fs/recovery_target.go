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
	root, err := containerCgroupRoot(container.PID)
	if err != nil {
		return 0, err
	}
	return findNamespaceProcess(ctx, root, fault.Namespace)
}

func containerCgroupRoot(pid uint32) (string, error) {
	paths, err := cgroups.ParseCgroupFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	path, base := paths[""], "/sys/fs/cgroup"
	if path == "" {
		path = paths["pids"]
		var root string
		base, root, err = cgroups.FindCgroupMountpointAndRoot("", "pids")
		if err != nil {
			return "", err
		}
		path, err = filepath.Rel(root, path)
		if err != nil || path == ".." || strings.HasPrefix(path, "../") {
			return "", fmt.Errorf("container cgroup is outside its mount")
		}
	}
	path = strings.TrimSuffix(filepath.Clean(path), "/init.scope")
	if path == "" || path == "/" || path == "." {
		return "", fmt.Errorf("refusing to search host cgroup root")
	}
	return filepath.Join(base, path), nil
}

func findNamespaceProcess(ctx context.Context, root string, namespace uint64) (uint32, error) {
	var found uint32
	var oldest uint64
	err := walkCgroupProcesses(ctx, root, func(pid uint32) {
		if !inMountNamespace(pid, namespace) {
			return
		}
		start, err := state.ProcessStartTime(pid)
		if err == nil && (found == 0 || start < oldest || start == oldest && pid < found) {
			found = pid
			oldest = start
		}
	})
	if err != nil {
		return 0, err
	}
	if found == 0 {
		return 0, fmt.Errorf("no live process in mount namespace %d", namespace)
	}
	return found, nil
}

func findContainerNamespaces(ctx context.Context, root string) (map[uint64]uint32, error) {
	type candidate struct {
		pid   uint32
		start uint64
	}
	namespaces := make(map[uint64]candidate)
	err := walkCgroupProcesses(ctx, root, func(pid uint32) {
		var ns unix.Stat_t
		if unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &ns) != nil {
			return
		}
		start, err := state.ProcessStartTime(pid)
		if err == nil && (namespaces[ns.Ino].pid == 0 || start < namespaces[ns.Ino].start || start == namespaces[ns.Ino].start && pid < namespaces[ns.Ino].pid) {
			namespaces[ns.Ino] = candidate{pid, start}
		}
	})
	if err != nil {
		return nil, err
	}
	result := make(map[uint64]uint32, len(namespaces))
	for ns, candidate := range namespaces {
		result[ns] = candidate.pid
	}
	return result, nil
}

func walkCgroupProcesses(ctx context.Context, root string, visit func(uint32)) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
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
			if err == nil {
				visit(uint32(pid))
			}
		}
		return nil
	})
}
