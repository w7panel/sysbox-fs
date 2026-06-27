//
// Copyright 2026 Nestybox, Inc.
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
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler/implementations"
	"golang.org/x/sys/unix"

	"github.com/sirupsen/logrus"
)

// Process names that should get the virtualized sysinfo view. The names are
// matched against /proc/<pid>/exe basename and /proc/<pid>/comm only; command
// arguments are intentionally ignored to avoid accidental matches.
var sysinfoVirtualizedProcessNames = []string{
	"free",
}

const sysinfoVirtualizationCacheTTL = 2 * time.Second

type sysinfoVirtualizationCacheEntry struct {
	virtualized bool
	expiresAt   time.Time
}

var sysinfoVirtualizationCache = struct {
	sync.Mutex
	entries map[uint32]sysinfoVirtualizationCacheEntry
}{
	entries: map[uint32]sysinfoVirtualizationCacheEntry{},
}

func (t *syscallTracer) processSysinfo(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	addr := req.Data.Args[0]
	if addr == 0 {
		return t.createErrorResponse(req.ID, syscall.EFAULT), nil
	}
	if !shouldVirtualizeSysinfo(req.Pid) {
		return t.createContinueResponse(req.ID), nil
	}

	mem, ok := implementations.SysinfoMemoryForPid(req.Pid)
	if !ok {
		return t.createContinueResponse(req.ID), nil
	}

	info := unix.Sysinfo_t{}
	if err := unix.Sysinfo(&info); err != nil {
		return nil, err
	}

	info.Totalram = mem.TotalRAM
	info.Freeram = mem.FreeRAM
	info.Sharedram = mem.SharedRAM
	info.Bufferram = mem.BufferRAM
	info.Totalswap = mem.TotalSwap
	info.Freeswap = mem.FreeSwap
	info.Totalhigh = 0
	info.Freehigh = 0
	info.Unit = 1

	size := int(unsafe.Sizeof(info))
	data := make([]byte, size)
	copy(data, unsafe.Slice((*byte)(unsafe.Pointer(&info)), size))

	if err := t.memParser.WriteSyscallBytesArgs(req.Pid, []memParserDataElem{{
		addr: addr,
		size: size,
		data: data,
	}}); err != nil {
		return nil, err
	}

	logrus.Debugf("Handled sysinfo syscall from pid %d: totalram=%d freeram=%d totalswap=%d freeswap=%d",
		req.Pid, info.Totalram, info.Freeram, info.Totalswap, info.Freeswap)

	return t.createSuccessResponse(req.ID), nil
}

func shouldVirtualizeSysinfo(pid uint32) bool {
	if virtualized, ok := sysinfoVirtualizationCacheGet(pid); ok {
		return virtualized
	}

	exe, _ := processExe(pid)
	exeName := filepath.Base(exe)
	if isVirtualizedSysinfoProcess(exeName) {
		sysinfoVirtualizationCachePut(pid, true)
		return true
	}

	comm, err := processComm(pid)
	virtualized := err == nil && isVirtualizedSysinfoProcess(comm)
	sysinfoVirtualizationCachePut(pid, virtualized)
	return virtualized
}

func sysinfoVirtualizationCacheGet(pid uint32) (bool, bool) {
	sysinfoVirtualizationCache.Lock()
	defer sysinfoVirtualizationCache.Unlock()

	entry, ok := sysinfoVirtualizationCache.entries[pid]
	if !ok {
		return false, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(sysinfoVirtualizationCache.entries, pid)
		return false, false
	}
	return entry.virtualized, true
}

func sysinfoVirtualizationCachePut(pid uint32, virtualized bool) {
	sysinfoVirtualizationCache.Lock()
	defer sysinfoVirtualizationCache.Unlock()

	sysinfoVirtualizationCache.entries[pid] = sysinfoVirtualizationCacheEntry{
		virtualized: virtualized,
		expiresAt:   time.Now().Add(sysinfoVirtualizationCacheTTL),
	}
}

func sysinfoVirtualizationCacheReset() {
	sysinfoVirtualizationCache.Lock()
	defer sysinfoVirtualizationCache.Unlock()

	sysinfoVirtualizationCache.entries = map[uint32]sysinfoVirtualizationCacheEntry{}
}

func isVirtualizedSysinfoProcess(processName string) bool {
	for _, name := range sysinfoVirtualizedProcessNames {
		if processName == name {
			return true
		}
	}
	return false
}

func processComm(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func processExe(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}
