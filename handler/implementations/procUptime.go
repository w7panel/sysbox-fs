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
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/uptime handler
//

type ProcUptime struct {
	domain.HandlerBase
}

type procUptimeSnapshot struct {
	data      []byte
	createdAt time.Time
}

const procUptimeSnapshotTTL = 100 * time.Millisecond

var procUptimeSnapshots = struct {
	sync.Mutex
	entries map[string]procUptimeSnapshot
}{
	entries: make(map[string]procUptimeSnapshot),
}

var ProcUptime_Handler = &ProcUptime{
	domain.HandlerBase{
		Name:    "ProcUptime",
		Path:    "/proc/uptime",
		Enabled: true,
	},
}

func (h *ProcUptime) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	info := &domain.FileInfo{
		Fname:    resource,
		Fmode:    os.FileMode(uint32(0444)),
		FmodTime: time.Now(),
		Fsize:    4096,
	}

	return info, nil
}

func (h *ProcUptime) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (bool, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	flags := n.OpenFlags()

	if flags&syscall.O_WRONLY == syscall.O_WRONLY ||
		flags&syscall.O_RDWR == syscall.O_RDWR {
		return false, fuse.IOerror{Code: syscall.EACCES}
	}

	return false, nil
}

func (h *ProcUptime) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	return h.readUptime(n, req)
}

func (h *ProcUptime) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	return 0, nil
}

func (h *ProcUptime) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	return nil, nil
}

func (h *ProcUptime) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return "", nil
}

func (h *ProcUptime) GetName() string {
	return h.Name
}

func (h *ProcUptime) GetPath() string {
	return h.Path
}

func (h *ProcUptime) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcUptime) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcUptime) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcUptime) GetResourcesList() []string {

	var resources []string

	for resourceKey, resource := range h.EmuResourceMap {
		resource.Mutex.Lock()
		if !resource.Enabled {
			resource.Mutex.Unlock()
			continue
		}
		resource.Mutex.Unlock()

		resources = append(resources, filepath.Join(h.GetPath(), resourceKey))
	}

	return resources
}

func (h *ProcUptime) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcUptime) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

func (h *ProcUptime) readUptime(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing %v Read() method", h.Name)

	cntr := req.Container

	//
	// We can assume that by the time a user generates a request to read
	// /proc/uptime, the embedding container has been fully initialized,
	// so Ctime() is already holding a valid value.
	//
	ctime := cntr.Ctime()

	// Calculate container's uptime, convert it to float to obtain required
	// precission (as per host FS), and finally format it into string for
	// storage purposes.
	//
	// The first column in /proc/uptime is uptime in seconds, while the second
	// column is cumulative idle time across the CPUs visible to the container.
	//
	data := procUptimeData(req, ctime, time.Now())

	if req.Offset >= int64(len(data)) {
		return 0, io.EOF
	}

	copied := copy(req.Data, data[req.Offset:])
	return copied, nil
}

func procUptimeData(req *domain.HandlerRequest, ctime, now time.Time) []byte {
	key := procUptimeSnapshotKey(req)

	procUptimeSnapshots.Lock()
	defer procUptimeSnapshots.Unlock()
	protectedKey := ""
	if req.Offset > 0 {
		protectedKey = key
	}
	pruneExpiredProcUptimeSnapshots(now, protectedKey)

	snapshot, ok := procUptimeSnapshots.entries[key]
	if ok && (req.Offset > 0 || now.Sub(snapshot.createdAt) < procUptimeSnapshotTTL) {
		return snapshot.data
	}

	uptime := containerUptime(ctime, now)
	idle := containerIdleFromReq(req, uptime)
	data := []byte(fmt.Sprintf("%.2f %.2f\n", uptime, idle))
	procUptimeSnapshots.entries[key] = procUptimeSnapshot{
		data:      data,
		createdAt: now,
	}
	return data
}

func pruneExpiredProcUptimeSnapshots(now time.Time, protectedKey string) {
	for key, snapshot := range procUptimeSnapshots.entries {
		if key == protectedKey {
			continue
		}
		if now.Sub(snapshot.createdAt) >= procUptimeSnapshotTTL {
			delete(procUptimeSnapshots.entries, key)
		}
	}
}

func procUptimeSnapshotKey(req *domain.HandlerRequest) string {
	if req.Container != nil && req.Container.ID() != "" {
		return req.Container.ID()
	}
	return fmt.Sprintf("pid:%d", req.Pid)
}

func containerUptime(ctime, now time.Time) float64 {
	if now.Before(ctime) {
		return 0
	}

	return now.Sub(ctime).Seconds()
}

func containerIdleFromReq(req *domain.HandlerRequest, uptime float64) float64 {
	cpus := effectiveCPUCount(req)
	if cpus <= 0 {
		cpus = 1
	}
	usage := cpuUsageFromCgroup(cgroupForReq(req))
	return containerIdleFromUsage(uptime, cpus, usage.UsageSeconds)
}

func containerIdleFromUsage(uptime float64, cpus int, usageSeconds float64) float64 {
	if uptime <= 0 {
		return 0
	}
	if cpus <= 0 {
		cpus = 1
	}

	capacity := uptime * float64(cpus)
	idle := capacity - usageSeconds
	if idle < 0 {
		return 0
	}
	if idle > capacity {
		return capacity
	}
	return idle
}

// containerIdleFromCgroup is retained for older unit tests and callers; new
// handler paths should use containerIdleFromReq so CPU limits are considered.
func containerIdleFromCgroup(cntr domain.ContainerIface, uptime float64) float64 {
	if uptime <= 0 {
		return 0
	}
	if cntr == nil {
		return uptime
	}

	req := &domain.HandlerRequest{Container: cntr}
	cpus := effectiveCPUCount(req)
	if cpus <= 0 {
		cpus = 1
	}
	return containerIdleFromUsage(uptime, cpus, cpuUsageFromCgroup(cgroupForReq(req)).UsageSeconds)
}
