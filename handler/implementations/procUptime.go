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
	"strconv"
	"strings"
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

	// /proc/uptime is not seekable
	return true, nil
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

	// We are dealing with a single integer element being read, so we can save
	// some cycles by returning right away if offset is any higher than zero.
	if req.Offset > 0 {
		return 0, io.EOF
	}

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
	// column is cumulative CPU idle time. The host's idle/uptime ratio gives us
	// a better approximation of the container's idle time than mirroring the
	// uptime value, especially on multi-core hosts where idle time can exceed
	// elapsed uptime.
	//
	uptime := containerUptime(ctime, time.Now())
	idle := uptime

	hostUptime, hostIdle, err := readHostUptime()
	if err != nil {
		logrus.Warnf("Unable to read host /proc/uptime: %s", err)
	} else {
		idle = containerIdleApprox(uptime, hostUptime, hostIdle)
	}

	uptimeStr := fmt.Sprintf("%.2f %.2f\n", uptime, idle)

	req.Data = []byte(uptimeStr)

	return len(req.Data), nil
}

func containerUptime(ctime, now time.Time) float64 {
	if now.Before(ctime) {
		return 0
	}

	return now.Sub(ctime).Seconds()
}

func containerIdleApprox(uptime, hostUptime, hostIdle float64) float64 {
	if uptime <= 0 {
		return 0
	}

	if hostUptime <= 0 || hostIdle < 0 {
		return uptime
	}

	return uptime * (hostIdle / hostUptime)
}

func readHostUptime() (float64, float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, 0, err
	}

	return parseProcUptime(string(data))
}

func parseProcUptime(data string) (float64, float64, error) {
	fields := strings.Fields(data)
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("invalid /proc/uptime content: %q", data)
	}

	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, 0, err
	}

	idle, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0, 0, err
	}

	return uptime, idle, nil
}
