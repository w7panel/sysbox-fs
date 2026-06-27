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
	"strconv"
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

type sysinfoVirtualizationCacheKey struct {
	pid       uint32
	startTime uint64
}

var sysinfoVirtualizationCache = struct {
	sync.Mutex
	entries map[sysinfoVirtualizationCacheKey]sysinfoVirtualizationCacheEntry
}{
	entries: map[sysinfoVirtualizationCacheKey]sysinfoVirtualizationCacheEntry{},
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
	startTime, hasStartTime := processStartTime(pid)
	if hasStartTime {
		if virtualized, ok := sysinfoVirtualizationCacheGet(pid, startTime); ok {
			return virtualized
		}
	}

	exe, _ := processExe(pid)
	exeName := filepath.Base(exe)
	if isVirtualizedSysinfoProcess(exeName) {
		if hasStartTime {
			sysinfoVirtualizationCachePut(pid, startTime, true)
		}
		return true
	}

	comm, err := processComm(pid)
	virtualized := err == nil && isVirtualizedSysinfoProcess(comm)
	if hasStartTime {
		sysinfoVirtualizationCachePut(pid, startTime, virtualized)
	}
	return virtualized
}

func sysinfoVirtualizationCacheGet(pid uint32, startTime uint64) (bool, bool) {
	sysinfoVirtualizationCache.Lock()
	defer sysinfoVirtualizationCache.Unlock()

	entry, ok := sysinfoVirtualizationCache.entries[sysinfoVirtualizationCacheKey{pid: pid, startTime: startTime}]
	if !ok {
		return false, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(sysinfoVirtualizationCache.entries, sysinfoVirtualizationCacheKey{pid: pid, startTime: startTime})
		return false, false
	}
	return entry.virtualized, true
}

func sysinfoVirtualizationCachePut(pid uint32, startTime uint64, virtualized bool) {
	sysinfoVirtualizationCache.Lock()
	defer sysinfoVirtualizationCache.Unlock()

	now := time.Now()
	for key, entry := range sysinfoVirtualizationCache.entries {
		if now.After(entry.expiresAt) {
			delete(sysinfoVirtualizationCache.entries, key)
		}
	}

	sysinfoVirtualizationCache.entries[sysinfoVirtualizationCacheKey{pid: pid, startTime: startTime}] = sysinfoVirtualizationCacheEntry{
		virtualized: virtualized,
		expiresAt:   now.Add(sysinfoVirtualizationCacheTTL),
	}
}

func sysinfoVirtualizationCacheReset() {
	sysinfoVirtualizationCache.Lock()
	defer sysinfoVirtualizationCache.Unlock()

	sysinfoVirtualizationCache.entries = map[sysinfoVirtualizationCacheKey]sysinfoVirtualizationCacheEntry{}
}

func processStartTime(pid uint32) (uint64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}

	stat := string(data)
	commEnd := strings.LastIndex(stat, ")")
	if commEnd == -1 || commEnd+2 >= len(stat) {
		return 0, false
	}

	fields := strings.Fields(stat[commEnd+2:])
	if len(fields) < 20 {
		return 0, false
	}

	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return startTime, true
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
