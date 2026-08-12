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
	"github.com/nestybox/sysbox-fs/domain"
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

// isChildUsernsSpecialMount reports whether a procfs/sysfs mount request
// comes from a process in a child user namespace distinct from the container
// init's. Such nested (L2) mounts are executed directly by the requesting
// process because the sysbox-fs nsenter helper runs as host root (kuid 0),
// which the child userns maps to the overflow uid, so it cannot mount the
// L2-owned mount namespace on the caller's behalf.
func isChildUsernsSpecialMount(
	process domain.ProcessIface,
	cntr domain.ContainerIface,
	fstype string) bool {

	if fstype != "proc" && fstype != "sysfs" {
		return false
	}
	if process == nil || cntr == nil || cntr.InitProc() == nil {
		return false
	}
	processUserns, err := process.UserNsInode()
	if err != nil {
		return false
	}
	containerUserns, err := cntr.InitProc().UserNsInode()
	if err != nil {
		return false
	}
	return processUserns != containerUserns
}
