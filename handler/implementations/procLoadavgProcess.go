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
)

func descendantProcessCount(initPID int) int {
	parents := processParentMap()
	if len(parents) == 0 {
		return 0
	}

	count := 0
	for pid := range parents {
		if pid == initPID || isDescendantPID(pid, initPID, parents) {
			count++
		}
	}
	return count
}

func processParentMap() map[int]int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	parents := map[int]int{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		ppid, ok := processParentPID(pid)
		if ok {
			parents[pid] = ppid
		}
	}
	return parents
}

func processParentPID(pid int) (int, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		ppid, err := strconv.Atoi(fields[1])
		return ppid, err == nil
	}
	return 0, false
}

func isDescendantPID(pid, ancestor int, parents map[int]int) bool {
	seen := map[int]struct{}{}
	for pid > 1 {
		if pid == ancestor {
			return true
		}
		if _, ok := seen[pid]; ok {
			return false
		}
		seen[pid] = struct{}{}
		parent, ok := parents[pid]
		if !ok {
			return false
		}
		pid = parent
	}
	return false
}

func sameOrChildCgroupView(a, b cgroupView) bool {
	if a.v2Path != "" && b.v2Path != "" {
		return sameOrChildPath(a.v2Path, b.v2Path) || sameOrChildPath(b.v2Path, a.v2Path)
	}
	for ctrl, aPath := range a.v1 {
		if bPath, ok := b.v1[ctrl]; ok && (sameOrChildPath(aPath, bPath) || sameOrChildPath(bPath, aPath)) {
			return true
		}
	}
	return false
}

func sameOrChildPath(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	return child == parent || strings.HasPrefix(child, strings.TrimRight(parent, "/")+"/")
}

func namespacePID(hostPID int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", hostPID))
	if err != nil {
		return hostPID
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return hostPID
		}
		pid, err := strconv.Atoi(fields[len(fields)-1])
		if err == nil {
			return pid
		}
	}
	return hostPID
}
