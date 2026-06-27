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
	"sync"

	"github.com/nestybox/sysbox-fs/domain"
)

const loadavgPidNamespaceScanBudget = 4096

var loadavgPidNamespaceInitCache = newPidNamespaceInitCache(loadavgPidNamespaceScanBudget)

type pidNamespaceInitCache struct {
	mu       sync.RWMutex
	limit    int
	values   map[string]int
	validate func(string, int) bool
}

func newPidNamespaceInitCache(limit int) *pidNamespaceInitCache {
	return &pidNamespaceInitCache{
		limit:    limit,
		values:   make(map[string]int),
		validate: pidNamespaceInitCacheEntryValid,
	}
}

func loadavgNodeKey(req *domain.HandlerRequest) (string, int) {
	pid := int(os.Getpid())
	if req != nil && req.Pid != 0 {
		pid = int(req.Pid)
		if initPID := pidNamespaceInitPID(pid); initPID != 0 {
			pid = initPID
		}
	} else if req != nil && req.Container != nil && req.Container.InitPid() != 0 {
		pid = int(req.Container.InitPid())
		if id := req.Container.ID(); id != "" {
			return "container:" + id, pid
		}
	}

	cg := cgroupForPid(uint32(pid))
	cg = pruneInitScopeCgroup(cg)
	if cg.v2Path != "" {
		return "cpu:" + cg.v2Path, pid
	}
	if cg.v1["cpu"] != "" {
		return "cpu:" + cg.v1["cpu"], pid
	}
	if ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid)); err == nil {
		return "pidns:" + ns, pid
	}
	return fmt.Sprintf("pid:%d", pid), pid
}

func pidNamespaceInitPID(pid int) int {
	initNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		return 0
	}
	return loadavgPidNamespaceInitCache.lookupOrScan(initNS, func(limit int) (int, bool) {
		return scanPidNamespaceInitPID(initNS, limit)
	})
}

func (c *pidNamespaceInitCache) lookupOrScan(ns string, scan func(limit int) (int, bool)) int {
	c.mu.RLock()
	pid, ok := c.values[ns]
	c.mu.RUnlock()
	if ok && c.validate(ns, pid) {
		return pid
	}
	if ok {
		c.delete(ns)
	}

	pid, ok = scan(c.limit)
	if !ok {
		return 0
	}
	c.store(ns, pid)
	return pid
}

func (c *pidNamespaceInitCache) store(ns string, pid int) {
	c.mu.Lock()
	c.values[ns] = pid
	c.mu.Unlock()
}

func (c *pidNamespaceInitCache) delete(ns string) {
	c.mu.Lock()
	delete(c.values, ns)
	c.mu.Unlock()
}

func pidNamespaceInitCacheEntryValid(ns string, pid int) bool {
	currentNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil || currentNS != ns {
		return false
	}
	return namespacePID(pid) == 1
}

func scanPidNamespaceInitPID(initNS string, limit int) (int, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}

	scanned := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if scanned >= limit {
			break
		}
		scanned++
		hostPID, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		ns, err := os.Readlink(filepath.Join("/proc", entry.Name(), "ns/pid"))
		if err != nil || ns != initNS {
			continue
		}
		if namespacePID(hostPID) == 1 {
			return hostPID, true
		}
	}
	return 0, false
}
