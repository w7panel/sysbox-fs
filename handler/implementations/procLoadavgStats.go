//
// Copyright 2019-2023 Nestybox, Inc.
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

package implementations

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nestybox/sysbox-fs/domain"
)

func loadavgStatsForPID(pid int) (int, int, int) {
	cgTotal, cgRunning, cgLastPID, cgOK := cgroupTaskStats(pruneInitScopeCgroup(cgroupForPid(uint32(pid))))
	if cgOK && (cgTotal > 1 || cgRunning > 0) {
		return cgTotal, cgRunning, cgLastPID
	}
	if total, running, lastPID, ok := samePIDNamespaceStats(pid); ok && total > cgTotal {
		return total, running, lastPID
	}
	if total, running, lastPID, ok := containerProcStats(pid); ok && total > cgTotal {
		return total, running, lastPID
	}
	if cgOK {
		return cgTotal, cgRunning, cgLastPID
	}
	return visibleProcessStatsFromCgroup(cgroupForPid(uint32(pid)))
}
func visibleProcessStats(req *domain.HandlerRequest) (int, int, int) {
	if req.Pid != 0 {
		if total, running, lastPID, ok := samePIDNamespaceStats(int(req.Pid)); ok {
			return total, running, lastPID
		}
	}
	if req.Container != nil && req.Container.InitPid() != 0 {
		if total, running, lastPID, ok := samePIDNamespaceStats(int(req.Container.InitPid())); ok {
			return total, running, lastPID
		}
		if total, running, lastPID, ok := containerProcStats(int(req.Container.InitPid())); ok {
			return total, running, lastPID
		}
		count := descendantProcessCount(int(req.Container.InitPid()))
		if count > 0 {
			return count, 1, count
		}
	}

	return visibleProcessStatsFromCgroup(cgroupForReq(req))
}

func visibleProcessStatsFromCgroup(target cgroupView) (int, int, int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0, 0
	}
	count := 0
	running := 0
	lastPID := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if !sameOrChildCgroupView(target, cgroupForPid(uint32(pid))) {
			continue
		}
		count++
		nsPID := namespacePID(pid)
		if nsPID > lastPID {
			lastPID = nsPID
		}
		if state, ok := procState(filepath.Join("/proc", entry.Name(), "status")); ok && loadavgActiveState(state) {
			running++
		}
	}
	return count, running, lastPID
}
func samePIDNamespaceStats(initPID int) (int, int, int, bool) {
	initNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", initPID))
	if err != nil {
		return 0, 0, 0, false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0, 0, false
	}

	total := 0
	running := 0
	lastPID := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		hostPID, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		ns, err := os.Readlink(filepath.Join("/proc", entry.Name(), "ns/pid"))
		if err != nil || ns != initNS {
			continue
		}
		total++
		nsPID := namespacePID(hostPID)
		if nsPID > lastPID {
			lastPID = nsPID
		}
		if state, ok := procState(filepath.Join("/proc", entry.Name(), "status")); ok && loadavgActiveState(state) {
			running++
		}
	}
	return total, running, lastPID, total > 0
}

func containerProcStats(initPID int) (int, int, int, bool) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/root/proc", initPID))
	if err != nil {
		return 0, 0, 0, false
	}

	total := 0
	running := 0
	lastPID := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		total++
		if pid > lastPID {
			lastPID = pid
		}
		state, ok := procState(filepath.Join("/proc", strconv.Itoa(initPID), "root/proc", entry.Name(), "status"))
		if ok && loadavgActiveState(state) {
			running++
		}
	}
	return total, running, lastPID, total > 0
}

func procState(statusPath string) (string, bool) {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "State:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			return fields[1], true
		}
	}
	return "", false
}

func loadavgActiveState(state string) bool {
	return state == "R" || state == "D"
}

func namespacePIDFromStatus(statusPath string, fallback int) int {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return fallback
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return fallback
		}
		pid, err := strconv.Atoi(fields[len(fields)-1])
		if err == nil {
			return pid
		}
	}
	return fallback
}
