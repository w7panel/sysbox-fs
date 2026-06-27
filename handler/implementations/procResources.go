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
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/sirupsen/logrus"
)

type resourceReader func(*domain.HandlerRequest) ([]byte, error)

const (
	procStatClockTicksPerSecond = 100
	resourceSnapshotTTL         = 200 * time.Millisecond
	procStatStateStaleAfter     = 5 * time.Minute
	loadavgSampleInterval       = 5 * time.Second
	loadavgStaleAfter           = 5 * time.Minute
	loadavgCgroupDepth          = 3
	loadavgFShift               = uint64(11)
	loadavgFixed1               = uint64(1) << loadavgFShift
	loadavgExp1                 = uint64(1884)
	loadavgExp5                 = uint64(2014)
	loadavgExp15                = uint64(2037)
)

type readOnlyResource struct {
	domain.HandlerBase
	read      resourceReader
	snapshots map[string]resourceSnapshot
	mu        sync.Mutex
}

type resourceSnapshot struct {
	data      []byte
	createdAt time.Time
}

type SysinfoMemory struct {
	TotalRAM  uint64
	FreeRAM   uint64
	SharedRAM uint64
	BufferRAM uint64
	TotalSwap uint64
	FreeSwap  uint64
}

type procStatState struct {
	mu          sync.Mutex
	initialized bool
	lastSeen    time.Time
	lastAt      time.Time
	lastRaw     containerCPUUsage
	lastHost    [][]uint64
	view        [][]uint64
}

type procStatDelta struct {
	user   uint64
	system uint64
	idle   uint64
}

var (
	procStatStatesMu sync.Mutex
	procStatStates   = make(map[string]*procStatState)
)

func newReadOnlyResource(name, path string, read resourceReader) *readOnlyResource {
	return &readOnlyResource{
		HandlerBase: domain.HandlerBase{
			Name:    name,
			Path:    path,
			Enabled: true,
			EmuResourceMap: map[string]*domain.EmuResource{
				filepath.Base(path): {
					Kind:    domain.FileEmuResource,
					Mode:    os.FileMode(uint32(0444)),
					Size:    4096,
					Enabled: true,
				},
			},
		},
		read:      read,
		snapshots: make(map[string]resourceSnapshot),
	}
}

var (
	ProcCpuinfo_Handler                = newReadOnlyResource("ProcCpuinfo", "/proc/cpuinfo", readCPUInfo)
	ProcDiskstats_Handler              = newReadOnlyResource("ProcDiskstats", "/proc/diskstats", readDiskstats)
	ProcMeminfo_Handler                = newReadOnlyResource("ProcMeminfo", "/proc/meminfo", readMemInfo)
	ProcStat_Handler                   = newReadOnlyResource("ProcStat", "/proc/stat", readProcStat)
	ProcSlabinfo_Handler               = newReadOnlyResource("ProcSlabinfo", "/proc/slabinfo", readSlabinfo)
	ProcLoadavg_Handler                = newReadOnlyResource("ProcLoadavg", "/proc/loadavg", readLoadavg)
	ProcPressureIO_Handler             = newReadOnlyResource("ProcPressureIO", "/proc/pressure/io", readPressure("io", "blkio", "io.pressure"))
	ProcPressureCPU_Handler            = newReadOnlyResource("ProcPressureCPU", "/proc/pressure/cpu", readPressure("cpu", "cpu", "cpu.pressure"))
	ProcPressureMemory_Handler         = newReadOnlyResource("ProcPressureMemory", "/proc/pressure/memory", readPressure("memory", "memory", "memory.pressure"))
	SysDevicesSystemCpuOnline_Handler  = newReadOnlyResource("SysDevicesSystemCpuOnline", "/sys/devices/system/cpu/online", readCPUOnline)
	SysDevicesSystemCpuPresent_Handler = newReadOnlyResource("SysDevicesSystemCpuPresent", "/sys/devices/system/cpu/present", readCPUPresent)
)

func (h *readOnlyResource) Lookup(n domain.IOnodeIface, req *domain.HandlerRequest) (os.FileInfo, error) {
	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return &domain.FileInfo{
		Fname:    filepath.Base(h.Path),
		Fmode:    os.FileMode(uint32(0444)),
		FmodTime: time.Now(),
		Fsize:    4096,
	}, nil
}

func (h *readOnlyResource) Open(n domain.IOnodeIface, req *domain.HandlerRequest) (bool, error) {
	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	flags := n.OpenFlags()
	if flags&syscall.O_WRONLY == syscall.O_WRONLY ||
		flags&syscall.O_RDWR == syscall.O_RDWR {
		return false, fuse.IOerror{Code: syscall.EACCES}
	}

	return false, nil
}

func (h *readOnlyResource) Read(n domain.IOnodeIface, req *domain.HandlerRequest) (int, error) {
	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	data, err := h.snapshotData(req)
	if err != nil {
		return 0, err
	}

	if req.Offset >= int64(len(data)) {
		return 0, io.EOF
	}

	copied := copy(req.Data, data[req.Offset:])
	return copied, nil
}

func (h *readOnlyResource) snapshotData(req *domain.HandlerRequest) ([]byte, error) {
	key := h.snapshotKey(req)
	now := time.Now()

	h.mu.Lock()
	protectedKey := ""
	if req.Offset > 0 {
		protectedKey = key
	}
	h.pruneExpiredSnapshots(now, protectedKey)
	if snapshot, ok := h.snapshots[key]; ok && (req.Offset > 0 || now.Sub(snapshot.createdAt) < resourceSnapshotTTL) {
		data := snapshot.data
		h.mu.Unlock()
		return data, nil
	}
	h.mu.Unlock()

	data, err := h.read(req)
	if err != nil {
		return nil, err
	}

	h.mu.Lock()
	h.snapshots[key] = resourceSnapshot{
		data:      data,
		createdAt: now,
	}
	h.mu.Unlock()

	return data, nil
}

func (h *readOnlyResource) pruneExpiredSnapshots(now time.Time, protectedKey string) {
	for key, snapshot := range h.snapshots {
		if key == protectedKey {
			continue
		}
		if now.Sub(snapshot.createdAt) >= resourceSnapshotTTL {
			delete(h.snapshots, key)
		}
	}
}

func (h *readOnlyResource) snapshotKey(req *domain.HandlerRequest) string {
	id := ""
	if req.Container != nil {
		id = req.Container.ID()
	}
	if id == "" {
		id = fmt.Sprintf("pid:%d", req.Pid)
	}
	return h.Path + ":" + id
}

func (h *readOnlyResource) Write(n domain.IOnodeIface, req *domain.HandlerRequest) (int, error) {
	return 0, nil
}

func (h *readOnlyResource) ReadDirAll(n domain.IOnodeIface, req *domain.HandlerRequest) ([]os.FileInfo, error) {
	return nil, nil
}

func (h *readOnlyResource) ReadLink(n domain.IOnodeIface, req *domain.HandlerRequest) (string, error) {
	return "", nil
}

func (h *readOnlyResource) GetName() string {
	return h.Name
}

func (h *readOnlyResource) GetPath() string {
	return h.Path
}

func (h *readOnlyResource) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *readOnlyResource) GetEnabled() bool {
	return h.Enabled
}

func (h *readOnlyResource) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *readOnlyResource) GetResourcesList() []string {
	return []string{h.GetPath()}
}

func (h *readOnlyResource) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[filepath.Base(h.Path)]
	if !ok {
		return nil
	}
	return &resource.Mutex
}

func (h *readOnlyResource) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

type cgroupView struct {
	v2Path string
	v1     map[string]string
}

func cgroupForReq(req *domain.HandlerRequest) cgroupView {
	if req != nil && req.Pid != 0 {
		cg := cgroupForPid(req.Pid)
		if cg.v2Path != "" || len(cg.v1) > 0 {
			return cg
		}
	}

	pid := uint32(0)
	if req != nil && req.Container != nil && req.Container.InitPid() != 0 {
		pid = req.Container.InitPid()
	}
	if pid == 0 {
		pid = uint32(os.Getpid())
	}

	return cgroupForPid(pid)
}

func cgroupForPid(pid uint32) cgroupView {
	view := cgroupView{v1: make(map[string]string)}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return view
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[1] == "" {
			view.v2Path = filepath.Clean(parts[2])
			continue
		}
		for _, ctrl := range strings.Split(parts[1], ",") {
			view.v1[ctrl] = filepath.Clean(parts[2])
		}
	}

	return view
}

func (c cgroupView) readV2(name string) (string, bool) {
	if c.v2Path == "" {
		return "", false
	}
	return readFirstExisting(filepath.Join("/sys/fs/cgroup", c.v2Path, name))
}

func (c cgroupView) readV2Effective(name string, accept func(string) bool) (string, bool) {
	if c.v2Path == "" {
		return "", false
	}

	cgPath := filepath.Clean(c.v2Path)
	for {
		if data, ok := readFirstExisting(filepath.Join("/sys/fs/cgroup", cgPath, name)); ok && accept(data) {
			return data, true
		}
		if cgPath == "." || cgPath == "/" {
			break
		}
		cgPath = filepath.Dir(cgPath)
	}

	return "", false
}

func (c cgroupView) readV1(ctrl, name string) (string, bool) {
	path, ok := c.v1[ctrl]
	if !ok {
		return "", false
	}
	candidates := []string{
		filepath.Join("/sys/fs/cgroup", ctrl, path, name),
		filepath.Join("/sys/fs/cgroup", path, name),
	}
	return readFirstExisting(candidates...)
}

func readFirstExisting(paths ...string) (string, bool) {
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			return strings.TrimSpace(string(data)), true
		}
	}
	return "", false
}

func parseUintValue(s string) (uint64, bool) {
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.Fields(s)[0], 10, 64)
	return v, err == nil
}

type containerCPUUsage struct {
	UsageSeconds  float64
	UserSeconds   float64
	SystemSeconds float64
	PerCPUSeconds []float64
}

func cpuUsageFromCgroup(cg cgroupView) containerCPUUsage {
	if usage, ok := cpuUsageFromCgroupV2(cg); ok {
		return usage
	}
	if usage, ok := cpuUsageFromCgroupV1(cg); ok {
		return usage
	}
	return containerCPUUsage{}
}

func cpuUsageFromCgroupV2(cg cgroupView) (containerCPUUsage, bool) {
	data, ok := cg.readV2("cpu.stat")
	if !ok {
		return containerCPUUsage{}, false
	}

	values := map[string]uint64{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			values[fields[0]] = v
		}
	}

	usageUsec, ok := values["usage_usec"]
	if !ok {
		return containerCPUUsage{}, false
	}

	return containerCPUUsage{
		UsageSeconds:  float64(usageUsec) / 1_000_000,
		UserSeconds:   float64(values["user_usec"]) / 1_000_000,
		SystemSeconds: float64(values["system_usec"]) / 1_000_000,
	}, true
}

func cpuUsageFromCgroupV1(cg cgroupView) (containerCPUUsage, bool) {
	usage := containerCPUUsage{}
	ok := false

	if stat, statOk := cg.readV1("cpuacct", "cpuacct.stat"); statOk {
		for _, line := range strings.Split(stat, "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			v, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				continue
			}
			switch fields[0] {
			case "user":
				usage.UserSeconds = float64(v) / procStatClockTicksPerSecond
			case "system":
				usage.SystemSeconds = float64(v) / procStatClockTicksPerSecond
			}
		}
		ok = true
	}

	if total, totalOk := cg.readV1("cpuacct", "cpuacct.usage"); totalOk {
		if usageNs, parsed := parseUintValue(total); parsed {
			usage.UsageSeconds = float64(usageNs) / 1_000_000_000
			ok = true
		}
	}

	if perCPU, perCPUOk := cg.readV1("cpuacct", "cpuacct.usage_percpu"); perCPUOk {
		for _, field := range strings.Fields(perCPU) {
			usageNs, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				continue
			}
			usage.PerCPUSeconds = append(usage.PerCPUSeconds, float64(usageNs)/1_000_000_000)
		}
		ok = true
	}

	if usage.UsageSeconds == 0 {
		usage.UsageSeconds = usage.UserSeconds + usage.SystemSeconds
	}
	return usage, ok
}

func hostFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func passThroughProcResource(path string) resourceReader {
	return func(req *domain.HandlerRequest) ([]byte, error) {
		return hostFile(path)
	}
}

func readDiskstats(req *domain.HandlerRequest) ([]byte, error) {
	cg := pruneInitScopeCgroup(cgroupForReq(req))
	if data, ok := cg.readV2("io.stat"); ok && data != "" {
		return diskstatsFromIOStat(data), nil
	}
	if data, ok := diskstatsFromBlkIO(cg); ok {
		return data, nil
	}
	return hostFile("/proc/diskstats")
}

func readSlabinfo(req *domain.HandlerRequest) ([]byte, error) {
	cg := cgroupForReq(req)
	if data, ok := cg.readV1("memory", "memory.kmem.slabinfo"); ok && data != "" {
		return []byte(ensureTrailingNewline(data)), nil
	}
	return hostFile("/proc/slabinfo")
}

func readCPUOnline(req *domain.HandlerRequest) ([]byte, error) {
	count := effectiveCPUCount(req)
	if count > 0 {
		return []byte(cpuRangeForCount(count) + "\n"), nil
	}
	return hostFile("/sys/devices/system/cpu/online")
}

func readCPUPresent(req *domain.HandlerRequest) ([]byte, error) {
	count := effectiveCPUCount(req)
	if count > 0 {
		return []byte(cpuRangeForCount(count) + "\n"), nil
	}
	return hostFile("/sys/devices/system/cpu/present")
}

func readRawCPUSet(req *domain.HandlerRequest) (string, bool) {
	return readCPUSetFromCgroup(cgroupForReq(req))
}

func readCPUSetFromCgroup(cg cgroupView) (string, bool) {
	cg = pruneInitScopeCgroup(cg)
	if cpus, ok := cg.readV2("cpuset.cpus"); ok && cpus != "" {
		return cpus, true
	}
	if cpus, ok := cg.readV2("cpuset.cpus.effective"); ok && cpus != "" {
		return cpus, true
	}
	if cpus, ok := cg.readV2Effective("cpuset.cpus", func(s string) bool { return s != "" }); ok {
		return cpus, true
	}
	if cpus, ok := cg.readV2Effective("cpuset.cpus.effective", func(s string) bool { return s != "" }); ok {
		return cpus, true
	}
	if cpus, ok := cg.readV1("cpuset", "cpuset.cpus"); ok && cpus != "" {
		return cpus, true
	}
	if data, err := hostFile("/sys/devices/system/cpu/online"); err == nil {
		return strings.TrimSpace(string(data)), true
	}
	return "", false
}

func effectiveCPUCount(req *domain.HandlerRequest) int {
	cg := pruneInitScopeCgroup(cgroupForReq(req))
	limit := 0
	if online, ok := readRawCPUSet(req); ok {
		limit = countCPURange(online)
	}

	if quotaLimit := cpuQuotaLimit(cg); quotaLimit > 0 && (limit == 0 || quotaLimit < limit) {
		limit = quotaLimit
	}

	if limit <= 0 {
		return hostCPUCount()
	}
	return limit
}

func cpuQuotaLimit(cg cgroupView) int {
	if quota, ok := minCPUQuota(cg); ok {
		n := int(math.Ceil(quota))
		if n > 0 {
			if hostCount := hostCPUCount(); n > hostCount {
				return hostCount
			}
			return n
		}
	}
	return 0
}

func minCPUQuota(cg cgroupView) (float64, bool) {
	minQuota := 0.0
	found := false
	if cg.v2Path != "" {
		for _, path := range cgroupPathAncestors(cg.v2Path) {
			if data, ok := readFirstExisting(filepath.Join("/sys/fs/cgroup", path, "cpu.max")); ok {
				if quota, ok := parseCPUQuota(data); ok && (!found || quota < minQuota) {
					minQuota = quota
					found = true
				}
			}
		}
		return minQuota, found
	}
	if path := cg.v1["cpu"]; path != "" {
		for _, ancestor := range cgroupPathAncestors(path) {
			if quota, ok := readCPUQuotaV1At(ancestor); ok && (!found || quota < minQuota) {
				minQuota = quota
				found = true
			}
		}
	}
	return minQuota, found
}

func parseCPUQuota(data string) (float64, bool) {
	fields := strings.Fields(data)
	if len(fields) < 2 || fields[0] == "max" {
		return 0, false
	}
	quota, qerr := strconv.ParseFloat(fields[0], 64)
	period, perr := strconv.ParseFloat(fields[1], 64)
	if qerr != nil || perr != nil || quota < 0 || period <= 0 {
		return 0, false
	}
	return quota / period, true
}

func readCPUQuotaV1At(path string) (float64, bool) {
	quotaStr, quotaOK := readFirstExisting(
		filepath.Join("/sys/fs/cgroup", "cpu", path, "cpu.cfs_quota_us"),
		filepath.Join("/sys/fs/cgroup", path, "cpu.cfs_quota_us"),
	)
	if !quotaOK {
		return 0, false
	}
	periodStr, periodOK := readFirstExisting(
		filepath.Join("/sys/fs/cgroup", "cpu", path, "cpu.cfs_period_us"),
		filepath.Join("/sys/fs/cgroup", path, "cpu.cfs_period_us"),
	)
	if !periodOK {
		return 0, false
	}
	quota, qerr := strconv.ParseFloat(strings.TrimSpace(quotaStr), 64)
	period, perr := strconv.ParseFloat(strings.TrimSpace(periodStr), 64)
	if qerr != nil || perr != nil || quota < 0 || period <= 0 {
		return 0, false
	}
	return quota / period, true
}

func cgroupPathAncestors(path string) []string {
	path = filepath.Clean(path)
	ancestors := []string{}
	for {
		ancestors = append(ancestors, path)
		if path == "." || path == "/" {
			break
		}
		path = filepath.Dir(path)
	}
	return ancestors
}

func cpuRangeForCount(count int) string {
	if count <= 1 {
		return "0"
	}
	return fmt.Sprintf("0-%d", count-1)
}

func countCPURange(s string) int {
	count := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])
			if err1 == nil && err2 == nil && end >= start {
				count += end - start + 1
			}
			continue
		}
		if _, err := strconv.Atoi(part); err == nil {
			count++
		}
	}
	return count
}

func hostCPUCount() int {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 1
	}
	count := strings.Count(string(data), "\nprocessor")
	if strings.HasPrefix(string(data), "processor") {
		count++
	}
	if count == 0 {
		count = 1
	}
	return count
}

func readCPUInfo(req *domain.HandlerRequest) ([]byte, error) {
	data, err := hostFile("/proc/cpuinfo")
	if err != nil {
		return nil, err
	}
	cpuset, ok := readCPUSetFromCgroup(cgroupForReq(req))
	if !ok || cpuset == "" {
		return data, nil
	}
	return cpuInfoFromHost(data, cpuset, effectiveCPUCount(req)), nil
}

func cpuInfoFromHost(data []byte, cpuset string, limit int) []byte {
	blocks := bytes.Split(bytes.TrimSpace(data), []byte("\n\n"))
	if len(blocks) == 0 {
		return data
	}

	out := bytes.Buffer{}
	renumbered := 0
	for _, block := range blocks {
		lines := bytes.Split(block, []byte("\n"))
		hostCPU, ok := cpuInfoBlockProcessor(lines)
		if !ok || !cpuInCPUSet(hostCPU, cpuset) {
			continue
		}
		if limit > 0 && renumbered == limit {
			break
		}
		if out.Len() > 0 {
			out.WriteString("\n\n")
		}
		for j, line := range lines {
			if bytes.HasPrefix(line, []byte("processor")) {
				lines[j] = []byte(fmt.Sprintf("processor\t: %d", renumbered))
			}
		}
		out.Write(bytes.Join(lines, []byte("\n")))
		renumbered++
	}
	if out.Len() == 0 {
		return []byte{}
	}
	out.WriteByte('\n')
	return out.Bytes()
}

func cpuInfoBlockProcessor(lines [][]byte) (int, bool) {
	for _, line := range lines {
		if !bytes.HasPrefix(line, []byte("processor")) {
			continue
		}
		parts := bytes.SplitN(line, []byte(":"), 2)
		if len(parts) != 2 {
			return 0, false
		}
		cpu, err := strconv.Atoi(strings.TrimSpace(string(parts[1])))
		return cpu, err == nil
	}
	return 0, false
}

func cpuInCPUSet(cpu int, cpuset string) bool {
	for _, part := range strings.Split(cpuset, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])
			if err1 == nil && err2 == nil {
				if start > end {
					start, end = end, start
				}
				if cpu >= start && cpu <= end {
					return true
				}
			}
			continue
		}
		value, err := strconv.Atoi(part)
		if err == nil && cpu == value {
			return true
		}
	}
	return false
}

func readProcStat(req *domain.HandlerRequest) ([]byte, error) {
	data, err := hostFile("/proc/stat")
	if err != nil {
		return nil, err
	}
	limit := effectiveCPUCount(req)
	if limit <= 0 {
		return data, nil
	}

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	fieldCount, hostCPUs := parseProcStatHostCPUs(lines)

	out := bytes.Buffer{}
	totals, cpus := procStatCPUView(req, limit, fieldCount, time.Now(), hostCPUs)
	writeProcStatCPULine(&out, "cpu", totals)
	for i, cpu := range cpus {
		writeProcStatCPULine(&out, fmt.Sprintf("cpu%d", i), cpu)
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "cpu") {
			continue
		}
		if strings.HasPrefix(line, "btime ") && req.Container != nil {
			out.WriteString(fmt.Sprintf("btime %d\n", req.Container.Ctime().Unix()))
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

func procStatCPUTicks(req *domain.HandlerRequest, cpus int, fieldCount int, now time.Time) []uint64 {
	uptime := 0.0
	if req.Container != nil {
		uptime = containerUptime(req.Container.Ctime(), now)
	}

	return procStatCPUTicksFromUsage(uptime, cpus, fieldCount, cpuUsageFromCgroup(cgroupForReq(req)))
}

func procStatCPUView(req *domain.HandlerRequest, cpus int, fieldCount int, now time.Time, hostCPUs [][]uint64) ([]uint64, [][]uint64) {
	if fieldCount < 4 {
		fieldCount = 4
	}
	if cpus <= 0 {
		cpus = 1
	}

	cg := cgroupForProcStatReq(req)
	key := procStatStateKey(req, cg)
	state := procStatStateForKey(key, now)
	raw := cpuUsageFromCgroup(cg)

	state.mu.Lock()
	defer state.mu.Unlock()
	state.lastSeen = now

	if !state.initialized || procStatUsageReset(raw, state.lastRaw) || len(state.view) != cpus || procStatFieldCount(state.view) != fieldCount {
		state.view = procStatInitialCPUView(req, cpus, fieldCount, raw, now)
		state.lastRaw = raw
		state.lastHost = cloneProcStatCPUValues(hostCPUs)
		state.lastAt = now
		state.initialized = true
		return sumProcStatCPUs(state.view, fieldCount), cloneProcStatCPUValues(state.view)
	}

	elapsed := now.Sub(state.lastAt).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}

	delta := procStatUsageDelta(raw, state.lastRaw, elapsed, cpus)
	weights := procStatCPUWeights(cpus, raw, state.lastRaw, hostCPUs, state.lastHost)
	parts := splitProcStatDelta(delta, weights)
	for i := range state.view {
		procStatAddDelta(state.view[i], parts[i])
	}

	state.lastRaw = raw
	state.lastHost = cloneProcStatCPUValues(hostCPUs)
	state.lastAt = now

	return sumProcStatCPUs(state.view, fieldCount), cloneProcStatCPUValues(state.view)
}

func cgroupForProcStatReq(req *domain.HandlerRequest) cgroupView {
	if req.Pid != 0 {
		cg := cgroupForPid(req.Pid)
		if cg.v2Path != "" || len(cg.v1) > 0 {
			return cg
		}
	}
	return cgroupForReq(req)
}

func procStatStateKey(req *domain.HandlerRequest, cg cgroupView) string {
	if cg.v2Path != "" {
		return "v2:" + cg.v2Path
	}

	parts := make([]string, 0, len(cg.v1))
	for ctrl, path := range cg.v1 {
		if ctrl == "cpuacct" || ctrl == "cpu" || ctrl == "cpuset" {
			parts = append(parts, ctrl+":"+path)
		}
	}
	if len(parts) > 0 {
		sort.Strings(parts)
		return "v1:" + strings.Join(parts, "|")
	}

	if req.Container != nil && req.Container.ID() != "" {
		return "container:" + req.Container.ID()
	}
	return fmt.Sprintf("pid:%d", req.Pid)
}

func procStatStateForKey(key string, now time.Time) *procStatState {
	procStatStatesMu.Lock()
	defer procStatStatesMu.Unlock()

	for k, state := range procStatStates {
		state.mu.Lock()
		stale := !state.lastSeen.IsZero() && now.Sub(state.lastSeen) > procStatStateStaleAfter
		state.mu.Unlock()
		if stale {
			delete(procStatStates, k)
		}
	}

	state, ok := procStatStates[key]
	if !ok {
		state = &procStatState{}
		procStatStates[key] = state
	}
	return state
}

func procStatInitialCPUView(req *domain.HandlerRequest, cpus int, fieldCount int, raw containerCPUUsage, now time.Time) [][]uint64 {
	uptime := 0.0
	if req.Container != nil {
		uptime = containerUptime(req.Container.Ctime(), now)
	}
	total := procStatCPUTicksFromUsage(uptime, cpus, fieldCount, raw)
	view := make([][]uint64, cpus)
	for i := 0; i < cpus; i++ {
		view[i] = splitProcStatCPUTicks(total, cpus, i)
	}
	return view
}

func procStatUsageReset(cur, prev containerCPUUsage) bool {
	return cur.UsageSeconds < prev.UsageSeconds ||
		cur.UserSeconds < prev.UserSeconds ||
		cur.SystemSeconds < prev.SystemSeconds ||
		procStatPerCPUReset(cur.PerCPUSeconds, prev.PerCPUSeconds)
}

func procStatPerCPUReset(cur, prev []float64) bool {
	limit := len(cur)
	if len(prev) < limit {
		limit = len(prev)
	}
	for i := 0; i < limit; i++ {
		if cur[i] < prev[i] {
			return true
		}
	}
	return false
}

func procStatUsageDelta(cur, prev containerCPUUsage, elapsed float64, cpus int) procStatDelta {
	used := cur.UsageSeconds - prev.UsageSeconds
	if used < 0 {
		used = 0
	}
	user := cur.UserSeconds - prev.UserSeconds
	system := cur.SystemSeconds - prev.SystemSeconds
	if user < 0 {
		user = 0
	}
	if system < 0 {
		system = 0
	}
	if user+system == 0 && used > 0 {
		user = used
	}
	if used == 0 && user+system > 0 {
		used = user + system
	}
	if user+system > used && user+system > 0 {
		scale := used / (user + system)
		user *= scale
		system *= scale
	}

	capacity := elapsed * float64(cpus)
	if capacity < 0 {
		capacity = 0
	}
	if used > capacity {
		scale := 0.0
		if used > 0 {
			scale = capacity / used
		}
		used = capacity
		user *= scale
		system *= scale
	}
	idle := capacity - used
	if idle < 0 {
		idle = 0
	}

	return procStatDelta{
		user:   secondsToProcStatTicks(user),
		system: secondsToProcStatTicks(system),
		idle:   secondsToProcStatTicks(idle),
	}
}

func procStatCPUWeights(cpus int, cur, prev containerCPUUsage, hostCur, hostPrev [][]uint64) []uint64 {
	if weights := procStatPerCPUUsageWeights(cpus, cur.PerCPUSeconds, prev.PerCPUSeconds); len(weights) == cpus {
		return weights
	}
	if weights := procStatHostCPUWeights(cpus, hostCur, hostPrev); len(weights) == cpus {
		return weights
	}
	weights := make([]uint64, cpus)
	for i := range weights {
		weights[i] = 1
	}
	return weights
}

func procStatPerCPUUsageWeights(cpus int, cur, prev []float64) []uint64 {
	if len(cur) == 0 || len(prev) == 0 {
		return nil
	}
	weights := make([]uint64, cpus)
	limit := cpus
	if len(cur) < limit {
		limit = len(cur)
	}
	if len(prev) < limit {
		limit = len(prev)
	}
	total := uint64(0)
	for i := 0; i < limit; i++ {
		if cur[i] <= prev[i] {
			continue
		}
		weight := secondsToProcStatTicks(cur[i] - prev[i])
		weights[i] = weight
		total += weight
	}
	if total == 0 {
		return nil
	}
	return weights
}

func procStatHostCPUWeights(cpus int, cur, prev [][]uint64) []uint64 {
	if len(cur) == 0 || len(prev) == 0 {
		return nil
	}
	weights := make([]uint64, cpus)
	total := uint64(0)
	for i := 0; i < cpus && i < len(cur) && i < len(prev); i++ {
		weight := procStatBusyDelta(cur[i], prev[i])
		weights[i] = weight
		total += weight
	}
	if total == 0 {
		return nil
	}
	return weights
}

func procStatBusyDelta(cur, prev []uint64) uint64 {
	limit := len(cur)
	if len(prev) < limit {
		limit = len(prev)
	}
	delta := uint64(0)
	for i := 0; i < limit; i++ {
		if i == 3 {
			continue
		}
		if cur[i] > prev[i] {
			delta += cur[i] - prev[i]
		}
	}
	return delta
}

func splitProcStatDelta(delta procStatDelta, weights []uint64) []procStatDelta {
	parts := make([]procStatDelta, len(weights))
	splitProcStatValue(delta.user, weights, func(i int, v uint64) { parts[i].user += v })
	splitProcStatValue(delta.system, weights, func(i int, v uint64) { parts[i].system += v })
	splitProcStatValue(delta.idle, weights, func(i int, v uint64) { parts[i].idle += v })
	return parts
}

func splitProcStatValue(value uint64, weights []uint64, set func(int, uint64)) {
	if len(weights) == 0 {
		return
	}
	totalWeight := uint64(0)
	for _, weight := range weights {
		totalWeight += weight
	}
	if totalWeight == 0 {
		for i := range weights {
			weights[i] = 1
		}
		totalWeight = uint64(len(weights))
	}

	assigned := uint64(0)
	maxIndex := 0
	for i, weight := range weights {
		if weight > weights[maxIndex] {
			maxIndex = i
		}
		part := value * weight / totalWeight
		set(i, part)
		assigned += part
	}
	if assigned < value {
		set(maxIndex, value-assigned)
	}
}

func procStatAddDelta(cpu []uint64, delta procStatDelta) {
	if len(cpu) > 0 {
		cpu[0] += delta.user
	}
	if len(cpu) > 2 {
		cpu[2] += delta.system
	}
	if len(cpu) > 3 {
		cpu[3] += delta.idle
	}
}

func procStatFieldCount(cpus [][]uint64) int {
	if len(cpus) == 0 {
		return 0
	}
	return len(cpus[0])
}

func parseProcStatHostCPUs(lines []string) (int, [][]uint64) {
	fieldCount := 10
	cpus := [][]uint64{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "cpu" {
			if len(fields) > 1 {
				fieldCount = len(fields) - 1
			}
			continue
		}
		if !strings.HasPrefix(fields[0], "cpu") {
			if len(cpus) > 0 {
				break
			}
			continue
		}
		if _, err := strconv.Atoi(strings.TrimPrefix(fields[0], "cpu")); err != nil {
			continue
		}
		values := make([]uint64, fieldCount)
		for i := 1; i < len(fields) && i <= fieldCount; i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err == nil {
				values[i-1] = v
			}
		}
		cpus = append(cpus, values)
	}
	if fieldCount < 4 {
		fieldCount = 4
	}
	return fieldCount, cpus
}

func sumProcStatCPUs(cpus [][]uint64, fieldCount int) []uint64 {
	if fieldCount < 4 {
		fieldCount = 4
	}
	total := make([]uint64, fieldCount)
	for _, cpu := range cpus {
		for i := 0; i < len(cpu) && i < fieldCount; i++ {
			total[i] += cpu[i]
		}
	}
	return total
}

func cloneProcStatCPUValues(cpus [][]uint64) [][]uint64 {
	out := make([][]uint64, len(cpus))
	for i, cpu := range cpus {
		out[i] = append([]uint64(nil), cpu...)
	}
	return out
}

func procStatCPUTicksFromUsage(uptime float64, cpus int, fieldCount int, usage containerCPUUsage) []uint64 {
	if fieldCount < 4 {
		fieldCount = 4
	}
	if cpus <= 0 {
		cpus = 1
	}

	capacity := uptime * float64(cpus)
	used := usage.UsageSeconds
	if used > capacity {
		used = capacity
	}
	if used < 0 {
		used = 0
	}

	user := usage.UserSeconds
	system := usage.SystemSeconds
	if user+system == 0 && used > 0 {
		user = used
	}
	if user+system > used && user+system > 0 {
		scale := used / (user + system)
		user *= scale
		system *= scale
	}

	ticks := make([]uint64, fieldCount)
	ticks[0] = secondsToProcStatTicks(user)
	ticks[2] = secondsToProcStatTicks(system)
	ticks[3] = secondsToProcStatTicks(capacity - used)
	return ticks
}

func secondsToProcStatTicks(seconds float64) uint64 {
	if seconds <= 0 {
		return 0
	}
	return uint64(math.Round(seconds * procStatClockTicksPerSecond))
}

func splitProcStatCPUTicks(total []uint64, cpus int, index int) []uint64 {
	if cpus <= 0 {
		cpus = 1
	}

	out := make([]uint64, len(total))
	for i, v := range total {
		base := v / uint64(cpus)
		rem := v % uint64(cpus)
		out[i] = base
		if uint64(index) < rem {
			out[i]++
		}
	}
	return out
}

func writeProcStatCPULine(out *bytes.Buffer, name string, values []uint64) {
	out.WriteString(name)
	for _, v := range values {
		out.WriteString(fmt.Sprintf(" %d", v))
	}
	out.WriteByte('\n')
}

func readMemInfo(req *domain.HandlerRequest) ([]byte, error) {
	host, err := parseHostMeminfo()
	if err != nil {
		return hostFile("/proc/meminfo")
	}

	cg := cgroupForReq(req)
	limit, hasLimit := memoryLimit(cg)
	usage, hasUsage := memoryUsage(cg)
	if !hasLimit || limit == 0 || limit > host["MemTotal"]*1024 {
		return hostFile("/proc/meminfo")
	}
	if !hasUsage {
		usage = 0
	}

	totalKB := limit / 1024
	usedKB := usage / 1024
	availKB := uint64(0)
	if totalKB > usedKB {
		availKB = totalKB - usedKB
	}

	swapTotal, swapUsed := swapValues(cg)
	swapFree := uint64(0)
	if swapTotal > swapUsed {
		swapFree = swapTotal - swapUsed
	}
	memStat := memoryStatValues(cg)
	out := bytes.Buffer{}
	memAvailable := availKB + memStat.kb("active_file") + memStat.kb("inactive_file") + memStat.kb("slab_reclaimable")
	if memAvailable > totalKB {
		memAvailable = totalKB
	}
	writeMemLine(&out, "MemTotal", totalKB)
	writeMemLine(&out, "MemFree", availKB)
	writeMemLine(&out, "MemAvailable", memAvailable)
	writeMemLine(&out, "Buffers", 0)
	writeMemLine(&out, "Cached", memStat.kbOrHost("file", host, "Cached", availKB))
	writeMemLine(&out, "SwapCached", 0)
	writeMemLine(&out, "Active", memStat.kbSumOrHost([]string{"active_anon", "active_file"}, host, "Active", usedKB))
	writeMemLine(&out, "Inactive", memStat.kbSumOrHost([]string{"inactive_anon", "inactive_file"}, host, "Inactive", usedKB))
	writeMemLine(&out, "Active(anon)", memStat.kbOrHost("active_anon", host, "Active(anon)", usedKB))
	writeMemLine(&out, "Inactive(anon)", memStat.kbOrHost("inactive_anon", host, "Inactive(anon)", usedKB))
	writeMemLine(&out, "Active(file)", memStat.kbOrHost("active_file", host, "Active(file)", availKB))
	writeMemLine(&out, "Inactive(file)", memStat.kbOrHost("inactive_file", host, "Inactive(file)", availKB))
	writeMemLine(&out, "Unevictable", memStat.kbOrHost("unevictable", host, "Unevictable", usedKB))
	writeMemLine(&out, "Mlocked", minHost(host, "Mlocked", usedKB))
	writeMemLine(&out, "SwapTotal", swapTotal/1024)
	writeMemLine(&out, "SwapFree", swapFree/1024)
	writeMemLine(&out, "Dirty", memStat.kbOrHost("file_dirty", host, "Dirty", usedKB))
	writeMemLine(&out, "Writeback", memStat.kbOrHost("file_writeback", host, "Writeback", usedKB))
	writeMemLine(&out, "AnonPages", memStat.kbOrHost("anon", host, "AnonPages", usedKB))
	writeMemLine(&out, "Mapped", memStat.kbOrHost("file_mapped", host, "Mapped", usedKB))
	writeMemLine(&out, "Shmem", memStat.kbOrHost("shmem", host, "Shmem", usedKB))
	writeMemLine(&out, "KReclaimable", minHost(host, "KReclaimable", usedKB))
	writeMemLine(&out, "Slab", memStat.kbOrHost("slab", host, "Slab", usedKB))
	writeMemLine(&out, "SReclaimable", memStat.kbOrHost("slab_reclaimable", host, "SReclaimable", usedKB))
	writeMemLine(&out, "SUnreclaim", memStat.kbOrHost("slab_unreclaimable", host, "SUnreclaim", usedKB))
	writeMemLine(&out, "KernelStack", memStat.kbOrHost("kernel_stack", host, "KernelStack", usedKB))
	writeMemLine(&out, "PageTables", memStat.kbOrHost("pagetables", host, "PageTables", usedKB))
	writeMemLine(&out, "NFS_Unstable", 0)
	writeMemLine(&out, "Bounce", 0)
	writeMemLine(&out, "WritebackTmp", 0)
	writeMemLine(&out, "AnonHugePages", memStat.kbOrHost("anon_thp", host, "AnonHugePages", usedKB))
	writeMemLine(&out, "ShmemHugePages", 0)
	writeMemLine(&out, "ShmemPmdMapped", 0)
	return out.Bytes(), nil
}

func SysinfoMemoryForPid(pid uint32) (SysinfoMemory, bool) {
	host, err := parseHostMeminfo()
	if err != nil {
		return SysinfoMemory{}, false
	}

	cg := cgroupForPid(pid)
	limit, hasLimit := memoryLimit(cg)
	usage, hasUsage := memoryUsage(cg)
	if !hasLimit || limit == 0 || limit > host["MemTotal"]*1024 {
		return SysinfoMemory{}, false
	}
	if !hasUsage {
		usage = 0
	}

	totalKB := limit / 1024
	usedKB := usage / 1024
	freeKB := uint64(0)
	if totalKB > usedKB {
		freeKB = totalKB - usedKB
	}

	swapTotal, swapUsed := swapValues(cg)
	swapFree := uint64(0)
	if swapTotal > swapUsed {
		swapFree = swapTotal - swapUsed
	}

	memStat := memoryStatValues(cg)
	return SysinfoMemory{
		TotalRAM:  totalKB * 1024,
		FreeRAM:   freeKB * 1024,
		SharedRAM: memStat.kbOrHost("shmem", host, "Shmem", usedKB) * 1024,
		BufferRAM: 0,
		TotalSwap: swapTotal,
		FreeSwap:  swapFree,
	}, true
}

type memoryStat map[string]uint64

func memoryStatValues(cg cgroupView) memoryStat {
	if data, ok := cg.readV2MemoryStat(); ok {
		return parseMemoryStat(data, false)
	}
	if data, ok := cg.readV1("memory", "memory.stat"); ok {
		return parseMemoryStat(data, true)
	}
	return memoryStat{}
}

func parseMemoryStat(data string, preferTotal bool) memoryStat {
	values := memoryStat{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		key := fields[0]
		if preferTotal && strings.HasPrefix(key, "total_") {
			key = strings.TrimPrefix(key, "total_")
		}
		if _, exists := values[key]; !exists || strings.HasPrefix(fields[0], "total_") {
			values[key] = v
		}
		if key == "rss_huge" {
			values["anon_thp"] = v
		}
	}
	return values
}

func (m memoryStat) kb(key string) uint64 {
	return m[key] / 1024
}

func (m memoryStat) kbOrHost(key string, host map[string]uint64, hostKey string, max uint64) uint64 {
	if v, ok := m[key]; ok {
		return v / 1024
	}
	return minHost(host, hostKey, max)
}

func (m memoryStat) kbSumOrHost(keys []string, host map[string]uint64, hostKey string, max uint64) uint64 {
	sum := uint64(0)
	found := false
	for _, key := range keys {
		if v, ok := m[key]; ok {
			sum += v
			found = true
		}
	}
	if found {
		return sum / 1024
	}
	return minHost(host, hostKey, max)
}

func parseHostMeminfo() (map[string]uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	values := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			values[key] = v
		}
	}
	return values, nil
}

func memoryLimit(cg cgroupView) (uint64, bool) {
	if v, ok := cg.readV2Effective("memory.max", func(s string) bool {
		return s != "" && s != "max"
	}); ok {
		return parseUintValue(v)
	}
	return parseUintValueFromV1(cg, "memory", "memory.limit_in_bytes")
}

func memoryUsage(cg cgroupView) (uint64, bool) {
	if v, ok := cg.readV2MemoryUsage(); ok {
		return parseUintValue(v)
	}
	return parseUintValueFromV1(cg, "memory", "memory.usage_in_bytes")
}

func (c cgroupView) readV2MemoryStat() (string, bool) {
	return readV2MemoryStatFrom("/sys/fs/cgroup", c.v2Path)
}

func readV2MemoryStatFrom(base, v2Path string) (string, bool) {
	path, ok := effectiveV2MemoryCgroupPath(base, v2Path, "memory.stat")
	if !ok {
		return "", false
	}
	return readFirstExisting(filepath.Join(base, path, "memory.stat"))
}

func (c cgroupView) readV2MemoryUsage() (string, bool) {
	return readV2MemoryUsageFrom("/sys/fs/cgroup", c.v2Path)
}

func readV2MemoryUsageFrom(base, v2Path string) (string, bool) {
	path, ok := effectiveV2MemoryCgroupPath(base, v2Path, "memory.current")
	if !ok {
		return "", false
	}
	return readFirstExisting(filepath.Join(base, path, "memory.current"))
}

func effectiveV2MemoryCgroupPath(base, v2Path, requiredFile string) (string, bool) {
	if v2Path == "" {
		return "", false
	}

	cleanPath := filepath.Clean(v2Path)
	_, fallbackOk := readFirstExisting(filepath.Join(base, cleanPath, requiredFile))
	cgPath := filepath.Clean(v2Path)
	for {
		max, ok := readFirstExisting(filepath.Join(base, cgPath, "memory.max"))
		if ok && max != "" && max != "max" {
			if _, fileOk := readFirstExisting(filepath.Join(base, cgPath, requiredFile)); fileOk {
				return cgPath, true
			}
		}
		if cgPath == "." || cgPath == "/" {
			break
		}
		cgPath = filepath.Dir(cgPath)
	}

	if fallbackOk {
		return cleanPath, true
	}
	return "", false
}

func parseUintValueFromV1(cg cgroupView, ctrl, name string) (uint64, bool) {
	if v, ok := cg.readV1(ctrl, name); ok {
		return parseUintValue(v)
	}
	return 0, false
}

func swapValues(cg cgroupView) (uint64, uint64) {
	info := swapInfoForCgroup(cg)
	return info.totalKB * 1024, info.usedKB * 1024
}

type swapInfo struct {
	totalKB uint64
	usedKB  uint64
}

func swapInfoForCgroup(cg cgroupView) swapInfo {
	hostSwapTotal := hostSwapTotalKB()
	if info, ok := swapInfoV2(cg, hostSwapTotal); ok {
		return info
	}
	if info, ok := swapInfoV1(cg, hostSwapTotal); ok {
		return info
	}
	return swapInfo{}
}

func swapInfoV2(cg cgroupView, hostSwapTotalKB uint64) (swapInfo, bool) {
	if max, ok := cg.readV2Effective("memory.swap.max", func(s string) bool {
		return s != "" && s != "max"
	}); ok {
		usedBytes, _ := parseUintValueFromV2(cg, "memory.swap.current")
		return swapInfoV2FromMax(max, usedBytes, hostSwapTotalKB)
	}
	return swapInfo{}, false
}

func swapInfoV2FromMax(max string, usedBytes, hostSwapTotalKB uint64) (swapInfo, bool) {
	totalBytes, hasTotal := parseUintValue(max)
	if !hasTotal {
		return swapInfo{}, false
	}

	return boundedSwapInfo(totalBytes/1024, usedBytes/1024, hostSwapTotalKB, 1), true
}

func swapInfoV1(cg cgroupView, hostSwapTotalKB uint64) (swapInfo, bool) {
	memLimit, hasMemLimit := memoryLimit(cg)
	memswLimit, hasMemswLimit := parseUintValueFromV1(cg, "memory", "memory.memsw.limit_in_bytes")
	memUsage, _ := memoryUsage(cg)
	memswUsage, _ := parseUintValueFromV1(cg, "memory", "memory.memsw.usage_in_bytes")
	if !hasMemLimit || !hasMemswLimit || memswLimit <= memLimit {
		return swapInfo{}, false
	}

	usedKB := uint64(0)
	if memswUsage > memUsage {
		usedKB = (memswUsage - memUsage) / 1024
	}
	swappiness := cgroupSwappiness(cg)
	return swapInfoV1FromLimits(memLimit, memswLimit, usedKB, hostSwapTotalKB, swappiness)
}

func swapInfoV1FromLimits(memLimit, memswLimit, usedKB, hostSwapTotalKB, swappiness uint64) (swapInfo, bool) {
	if memswLimit <= memLimit || isCgroupV1UnlimitedLimit(memswLimit) {
		return swapInfo{}, false
	}

	totalKB := (memswLimit - memLimit) / 1024
	return boundedSwapInfo(totalKB, usedKB, hostSwapTotalKB, swappiness), true
}

func isCgroupV1UnlimitedLimit(limit uint64) bool {
	return limit >= uint64(math.MaxInt64/2)
}

func boundedSwapInfo(totalKB, usedKB, hostSwapTotalKB, swappiness uint64) swapInfo {
	if hostSwapTotalKB > 0 && totalKB > hostSwapTotalKB {
		totalKB = hostSwapTotalKB
	}
	if swappiness == 0 {
		totalKB = usedKB
	}
	if usedKB > totalKB {
		usedKB = totalKB
	}
	return swapInfo{totalKB: totalKB, usedKB: usedKB}
}

func cgroupSwappiness(cg cgroupView) uint64 {
	if value, ok := cg.readV1("memory", "memory.swappiness"); ok {
		if parsed, parsedOk := parseUintValue(value); parsedOk {
			return parsed
		}
	}
	return 1
}

func hostSwapTotalKB() uint64 {
	host, err := parseHostMeminfo()
	if err != nil {
		return 0
	}
	return host["SwapTotal"]
}

func parseUintValueFromV2(cg cgroupView, name string) (uint64, bool) {
	if v, ok := cg.readV2(name); ok {
		return parseUintValue(v)
	}
	return 0, false
}

func writeMemLine(out *bytes.Buffer, key string, value uint64) {
	out.WriteString(fmt.Sprintf("%-16s %8d kB\n", key+":", value))
}

func minHost(host map[string]uint64, key string, max uint64) uint64 {
	v := host[key]
	if v > max {
		return max
	}
	return v
}

func readPressure(name, controller, cgroupFile string) resourceReader {
	return func(req *domain.HandlerRequest) ([]byte, error) {
		cg := pruneInitScopeCgroup(cgroupForReq(req))
		if data, ok := cg.readV2(cgroupFile); ok {
			return []byte(ensureTrailingNewline(data)), nil
		}
		if data, ok := cg.readV1(controller, cgroupFile); ok {
			return []byte(ensureTrailingNewline(data)), nil
		}
		return hostFile(filepath.Join("/proc/pressure", name))
	}
}

func readLoadavg(req *domain.HandlerRequest) ([]byte, error) {
	node := loadavgSamplerForReq(req)
	return []byte(node.format()), nil
}

type loadavgNode struct {
	key         string
	samplePID   int
	avenrun     [3]uint64
	running     int
	total       int
	lastPID     int
	lastSeen    time.Time
	lastRefresh time.Time
}

type loadavgSamplerState struct {
	sync.Mutex
	once  sync.Once
	nodes map[string]*loadavgNode
}

var loadavgSampler = &loadavgSamplerState{
	nodes: make(map[string]*loadavgNode),
}

func loadavgSamplerForReq(req *domain.HandlerRequest) *loadavgNode {
	loadavgSampler.once.Do(func() {
		go loadavgSampler.run()
	})

	key, samplePID := loadavgNodeKey(req)
	now := time.Now()

	loadavgSampler.Lock()
	node := loadavgSampler.nodes[key]
	if node == nil {
		node = &loadavgNode{
			key:         key,
			samplePID:   samplePID,
			total:       1,
			lastPID:     namespacePID(samplePID),
			lastSeen:    now,
			lastRefresh: now,
		}
		loadavgSampler.nodes[key] = node
	} else {
		node.samplePID = samplePID
		node.lastSeen = now
	}
	loadavgSampler.Unlock()

	loadavgSampler.refreshIfDue(node, now)
	return node
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
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

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
		if namespacePID(hostPID) == 1 {
			return hostPID
		}
	}
	return 0
}

func (s *loadavgSamplerState) run() {
	ticker := time.NewTicker(loadavgSampleInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.Lock()
		nodes := make([]*loadavgNode, 0, len(s.nodes))
		now := time.Now()
		for key, node := range s.nodes {
			if now.Sub(node.lastSeen) > loadavgStaleAfter {
				delete(s.nodes, key)
				continue
			}
			nodes = append(nodes, node)
		}
		s.Unlock()

		for _, node := range nodes {
			s.refresh(node)
		}
	}
}

func (s *loadavgSamplerState) refresh(node *loadavgNode) {
	s.Lock()
	samplePID := node.samplePID
	s.Unlock()

	total, running, lastPID := loadavgStatsForPID(samplePID)
	total, running = normalizeLoadavgSample(total, running)

	s.Lock()
	node.avenrun[0] = calcLoadavg(node.avenrun[0], loadavgExp1, uint64(running))
	node.avenrun[1] = calcLoadavg(node.avenrun[1], loadavgExp5, uint64(running))
	node.avenrun[2] = calcLoadavg(node.avenrun[2], loadavgExp15, uint64(running))
	node.running = running
	node.total = total
	node.lastPID = lastPID
	if node.lastPID == 0 {
		node.lastPID = namespacePID(node.samplePID)
	}
	node.lastRefresh = time.Now()
	s.Unlock()
}

func (s *loadavgSamplerState) refreshIfDue(node *loadavgNode, now time.Time) {
	s.Lock()
	due := now.Sub(node.lastRefresh) >= loadavgSampleInterval
	s.Unlock()
	if due {
		s.refresh(node)
	}
}

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

func normalizeLoadavgSample(total, running int) (int, int) {
	if total == 0 {
		total = 1
	}
	if running > total {
		total = running
	}
	return total, running
}

func calcLoadavg(load, exp, active uint64) uint64 {
	if active > 0 {
		active *= loadavgFixed1
	}
	newLoad := load*exp + active*(loadavgFixed1-exp)
	if active >= load {
		newLoad += loadavgFixed1 - 1
	}
	return newLoad / loadavgFixed1
}

func (n *loadavgNode) format() string {
	loadavgSampler.Lock()
	a := n.avenrun[0] + loadavgFixed1/200
	b := n.avenrun[1] + loadavgFixed1/200
	c := n.avenrun[2] + loadavgFixed1/200
	running := n.running
	total := n.total
	lastPID := n.lastPID
	samplePID := n.samplePID
	loadavgSampler.Unlock()

	if total == 0 {
		total = 1
	}
	if lastPID == 0 {
		lastPID = namespacePID(samplePID)
	}

	return fmt.Sprintf("%d.%02d %d.%02d %d.%02d %d/%d %d\n",
		loadavgInt(a), loadavgFrac(a),
		loadavgInt(b), loadavgFrac(b),
		loadavgInt(c), loadavgFrac(c),
		running, total, lastPID)
}

func loadavgInt(v uint64) uint64 {
	return v >> loadavgFShift
}

func loadavgFrac(v uint64) uint64 {
	return loadavgInt((v & (loadavgFixed1 - 1)) * 100)
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

func diskstatsFromIOStat(data string) []byte {
	stats := parseIOStatValues(data)
	return diskstatsFromIOStatValues(stats, diskstatsHostDevices())
}

func diskstatsFromIOStatValues(stats map[string]map[string]uint64, devices []diskDevice) []byte {
	out := bytes.Buffer{}
	for _, device := range devices {
		values := stats[device.key()]
		if len(values) == 0 {
			continue
		}
		writeIOStatDiskstatsLine(&out, device, values)
	}
	return out.Bytes()
}

func parseIOStatValues(data string) map[string]map[string]uint64 {
	out := map[string]map[string]uint64{}
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.Contains(fields[0], ":") {
			continue
		}
		dev := fields[0]
		for _, field := range fields[1:] {
			kv := strings.SplitN(field, "=", 2)
			if len(kv) != 2 {
				continue
			}
			v, err := strconv.ParseUint(kv[1], 10, 64)
			if err == nil {
				if out[dev] == nil {
					out[dev] = map[string]uint64{}
				}
				out[dev][kv[0]] = v
			}
		}
	}
	return out
}

func writeIOStatDiskstatsLine(out *bytes.Buffer, device diskDevice, values map[string]uint64) bool {
	readSectors := values["rbytes"] / 512
	writeSectors := values["wbytes"] / 512
	discardSectors := values["dbytes"] / 512
	if values["rios"]+values["wios"]+values["dios"]+readSectors+writeSectors+discardSectors == 0 {
		return false
	}
	out.WriteString(fmt.Sprintf("%d       %d %s %d 0 %d 0 %d 0 %d 0 0 0 0 %d 0 %d 0\n",
		device.major, device.minor, device.name,
		values["rios"], readSectors,
		values["wios"], writeSectors,
		values["dios"], discardSectors))
	return true
}

type blkIOStats struct {
	serviced     map[string]map[string]uint64
	merged       map[string]map[string]uint64
	serviceBytes map[string]map[string]uint64
	waitTime     map[string]map[string]uint64
	serviceTime  map[string]map[string]uint64
}

func diskstatsFromBlkIO(cg cgroupView) ([]byte, bool) {
	stats := blkIOStats{
		serviced:     readBlkIOValues(cg, "blkio.io_serviced_recursive", "blkio.throttle.io_serviced", "blkio.io_serviced"),
		merged:       readBlkIOValues(cg, "blkio.io_merged_recursive", "blkio.io_merged"),
		serviceBytes: readBlkIOValues(cg, "blkio.io_service_bytes_recursive", "blkio.throttle.io_service_bytes", "blkio.io_service_bytes"),
		waitTime:     readBlkIOValues(cg, "blkio.io_wait_time_recursive", "blkio.io_wait_time"),
		serviceTime:  readBlkIOValues(cg, "blkio.io_service_time_recursive", "blkio.io_service_time"),
	}
	if len(stats.serviced) == 0 && len(stats.serviceBytes) == 0 {
		return nil, false
	}

	return diskstatsFromBlkIOStats(stats, diskstatsHostDevices())
}

func diskstatsFromBlkIOStats(stats blkIOStats, devices []diskDevice) ([]byte, bool) {
	out := bytes.Buffer{}
	for _, device := range devices {
		writeBlkIODiskstatsLine(&out, device, stats)
	}
	return out.Bytes(), out.Len() > 0
}

func writeBlkIODiskstatsLine(out *bytes.Buffer, device diskDevice, stats blkIOStats) bool {
	dev := device.key()
	read := blkIOOp(stats.serviced, dev, "Read")
	write := blkIOOp(stats.serviced, dev, "Write")
	discard := blkIOOp(stats.serviced, dev, "Discard")
	readMerged := blkIOOp(stats.merged, dev, "Read")
	writeMerged := blkIOOp(stats.merged, dev, "Write")
	discardMerged := blkIOOp(stats.merged, dev, "Discard")
	readSectors := blkIOOp(stats.serviceBytes, dev, "Read") / 512
	writeSectors := blkIOOp(stats.serviceBytes, dev, "Write") / 512
	discardSectors := blkIOOp(stats.serviceBytes, dev, "Discard") / 512
	readTicks := nsToMs(blkIOOp(stats.serviceTime, dev, "Read") + blkIOOp(stats.waitTime, dev, "Read"))
	writeTicks := nsToMs(blkIOOp(stats.serviceTime, dev, "Write") + blkIOOp(stats.waitTime, dev, "Write"))
	discardTicks := nsToMs(blkIOOp(stats.serviceTime, dev, "Discard") + blkIOOp(stats.waitTime, dev, "Discard"))
	totalTicks := nsToMs(blkIOOp(stats.serviceTime, dev, "Total"))

	if read+write+discard+readMerged+writeMerged+discardMerged+readSectors+writeSectors+discardSectors+readTicks+writeTicks+discardTicks+totalTicks == 0 {
		return false
	}
	out.WriteString(fmt.Sprintf("%d       %d %s %d %d %d %d %d %d %d %d 0 %d 0 %d %d %d %d\n",
		device.major, device.minor, device.name,
		read, readMerged, readSectors, readTicks,
		write, writeMerged, writeSectors, writeTicks,
		totalTicks,
		discard, discardMerged, discardSectors, discardTicks))
	return true
}

func readBlkIOValues(cg cgroupView, names ...string) map[string]map[string]uint64 {
	for _, name := range names {
		if data, ok := cg.readV1("blkio", name); ok && data != "" {
			return parseBlkIOValues(data)
		}
	}
	return nil
}

func parseBlkIOValues(data string) map[string]map[string]uint64 {
	out := map[string]map[string]uint64{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || !strings.Contains(fields[0], ":") {
			continue
		}
		v, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			continue
		}
		if out[fields[0]] == nil {
			out[fields[0]] = map[string]uint64{}
		}
		out[fields[0]][fields[1]] = v
	}
	return out
}

func blkIOOp(values map[string]map[string]uint64, dev, op string) uint64 {
	if values == nil || values[dev] == nil {
		return 0
	}
	return values[dev][op]
}

func nsToMs(ns uint64) uint64 {
	return ns / 1_000_000
}

type diskDevice struct {
	major uint64
	minor uint64
	name  string
}

func (d diskDevice) key() string {
	return fmt.Sprintf("%d:%d", d.major, d.minor)
}

func diskDeviceFromKey(key string) (diskDevice, bool) {
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return diskDevice{}, false
	}
	major, majorErr := strconv.ParseUint(parts[0], 10, 64)
	minor, minorErr := strconv.ParseUint(parts[1], 10, 64)
	if majorErr != nil || minorErr != nil {
		return diskDevice{}, false
	}
	return diskDevice{major: major, minor: minor}, true
}

func diskstatsHostDevices() []diskDevice {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return nil
	}
	return parseDiskstatsDevices(string(data))
}

func parseDiskstatsDevices(data string) []diskDevice {
	devices := []diskDevice{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			major, majorErr := strconv.ParseUint(fields[0], 10, 64)
			minor, minorErr := strconv.ParseUint(fields[1], 10, 64)
			if majorErr == nil && minorErr == nil {
				devices = append(devices, diskDevice{
					major: major,
					minor: minor,
					name:  fields[2],
				})
			}
		}
	}
	return devices
}

func ensureTrailingNewline(data string) string {
	if strings.HasSuffix(data, "\n") {
		return data
	}
	return data + "\n"
}
