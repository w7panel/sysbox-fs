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
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func pruneInitScopeCgroup(cg cgroupView) cgroupView {
	cg.v2Path = pruneInitScopePath(cg.v2Path)
	for ctrl, path := range cg.v1 {
		cg.v1[ctrl] = pruneInitScopePath(path)
	}
	return cg
}

func pruneInitScopePath(path string) string {
	path = filepath.Clean(path)
	if path == "/init.scope" {
		return "/"
	}
	return strings.TrimSuffix(path, "/init.scope")
}

func cgroupTaskStats(cg cgroupView) (int, int, int, bool) {
	pids := cgroupProcessPIDs(cg)
	if len(pids) == 0 {
		return 0, 0, 0, false
	}

	total := 0
	running := 0
	lastPID := 0
	for pid := range pids {
		taskDir := filepath.Join("/proc", strconv.Itoa(pid), "task")
		entries, err := os.ReadDir(taskDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			tid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			total++
			statusPath := filepath.Join(taskDir, entry.Name(), "status")
			nsPID := namespacePIDFromStatus(statusPath, tid)
			if nsPID > lastPID {
				lastPID = nsPID
			}
			if state, ok := procState(statusPath); ok && loadavgActiveState(state) {
				running++
			}
		}
	}

	return total, running, lastPID, total > 0
}

func cgroupProcessPIDs(cg cgroupView) map[int]struct{} {
	pids := map[int]struct{}{}
	if cg.v2Path != "" {
		collectCgroupProcessPIDs(filepath.Join("/sys/fs/cgroup", cg.v2Path), loadavgCgroupDepth, pids)
		return pids
	}
	if path := cg.v1["cpu"]; path != "" {
		for _, base := range []string{
			filepath.Join("/sys/fs/cgroup", "cpu", path),
			filepath.Join("/sys/fs/cgroup", path),
		} {
			collectCgroupProcessPIDs(base, loadavgCgroupDepth, pids)
			if len(pids) > 0 {
				return pids
			}
		}
	}
	return pids
}

func collectCgroupProcessPIDs(dir string, depth int, pids map[int]struct{}) {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err == nil {
		for _, field := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(field)
			if err == nil {
				pids[pid] = struct{}{}
			}
		}
	}
	if depth <= 0 {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			collectCgroupProcessPIDs(filepath.Join(dir, entry.Name()), depth-1, pids)
		}
	}
}
