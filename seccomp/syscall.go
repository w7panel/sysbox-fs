//
// Copyright 2019-2020 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package seccomp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sys/unix"
)

// Syscall generic information / state.
type syscallCtx struct {
	syscallNum  int32                 // Value representing the syscall
	syscallName string                // Name of the syscall
	reqId       uint64                // Id associated to the syscall request
	pid         uint32                // Pid of the process generating the syscall
	uid         uint32                // Uid of the process generating the syscall
	gid         uint32                // Gid of the process generating the syscall
	cwd         string                // Cwd of process generating the syscall
	root        string                // Root of process generating the syscall
	processInfo domain.ProcessIface   // Process details associated to the syscall request
	cntr        domain.ContainerIface // Container hosting the process generating the syscall
	tracer      *syscallTracer        // Backpointer to the seccomp-tracer owning the syscall
}

func namespaceOwnerUsernsInode(pid uint32, nstype string) (domain.Inode, error) {
	path := fmt.Sprintf("/proc/%d/ns/%s", pid, nstype)
	ns, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer ns.Close()
	ownerFd, _, errno := unix.Syscall(unix.SYS_IOCTL, ns.Fd(), unix.NS_GET_USERNS, 0)
	if errno != 0 {
		return 0, errno
	}
	defer unix.Close(int(ownerFd))
	var st syscall.Stat_t
	if err := syscall.Fstat(int(ownerFd), &st); err != nil {
		return 0, err
	}
	return domain.Inode(st.Ino), nil
}

func (s *syscallCtx) nsenterNamespaces() *[]domain.NStype {
	// Nested identity still requires entering the L2 user namespace. The
	// caller is privileged in the L1 user namespace, and nsexec orders the
	// user namespace last so it can join the L2 pid/mount namespaces first.
	// Do not omit userns here: doing so makes ownership and mount operations
	// execute with L1 credentials and fails for an L2-owned mount namespace.
	if s.processInfo == nil || s.cntr == nil || s.cntr.InitProc() == nil {
		return &domain.AllNSs
	}

	processUserns, err := s.processInfo.UserNsInode()
	if err != nil {
		return &domain.AllNSs
	}
	containerUserns, err := s.cntr.InitProc().UserNsInode()
	if err != nil || processUserns == containerUserns {
		return &domain.AllNSs
	}
	parentUserns, err := s.processInfo.UserNsInodeParent()
	if err == nil && useParentUserns(processUserns, parentUserns, containerUserns) {
		return &domain.AllNSs
	}
	return &domain.AllNSs
}

func useParentUserns(processUserns, parentUserns, containerUserns domain.Inode) bool {
	return processUserns != containerUserns && parentUserns == containerUserns
}

// normalizeChildUsernsSpecialMountTarget handles mount notifications inherited
// across a nested Sysbox boundary. Resolving the tracee's procfd from L1 can
// produce an L1-visible path such as <L2-rootfs>/proc; PathAccess expects a path
// in L2 coordinates and would otherwise prepend the rootfs a second time.
func normalizeChildUsernsSpecialMountTarget(
	process domain.ProcessIface,
	cntr domain.ContainerIface,
	fstype, target string) (string, bool) {

	var expected string
	switch fstype {
	case "proc":
		expected = "/proc"
	case "sysfs":
		expected = "/sys"
	default:
		return target, false
	}
	if process == nil || cntr == nil || target == "" {
		return target, false
	}
	root := filepath.Clean(process.Root())
	cleanTarget := filepath.Clean(target)
	rootedTarget := filepath.Join(root, strings.TrimPrefix(expected, "/"))
	if cleanTarget != expected && cleanTarget != rootedTarget {
		return target, false
	}
	initProc := cntr.InitProc()
	if initProc == nil {
		return target, false
	}
	processUserns, err := process.UserNsInode()
	if err != nil {
		return target, false
	}
	containerUserns, err := initProc.UserNsInode()
	if err != nil {
		return target, false
	}
	if processUserns == containerUserns {
		return target, false
	}
	return expected, true
}
