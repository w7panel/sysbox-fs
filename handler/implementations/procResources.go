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

const procStatClockTicksPerSecond = 100

type readOnlyResource struct {
	domain.HandlerBase
	read resourceReader
}

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
		read: read,
	}
}

var (
	ProcCpuinfo_Handler               = newReadOnlyResource("ProcCpuinfo", "/proc/cpuinfo", readCPUInfo)
	ProcDiskstats_Handler             = newReadOnlyResource("ProcDiskstats", "/proc/diskstats", readDiskstats)
	ProcMeminfo_Handler               = newReadOnlyResource("ProcMeminfo", "/proc/meminfo", readMemInfo)
	ProcStat_Handler                  = newReadOnlyResource("ProcStat", "/proc/stat", readProcStat)
	ProcSlabinfo_Handler              = newReadOnlyResource("ProcSlabinfo", "/proc/slabinfo", readSlabinfo)
	ProcPressureIO_Handler            = newReadOnlyResource("ProcPressureIO", "/proc/pressure/io", readPressure("io"))
	ProcPressureCPU_Handler           = newReadOnlyResource("ProcPressureCPU", "/proc/pressure/cpu", readPressure("cpu"))
	ProcPressureMemory_Handler        = newReadOnlyResource("ProcPressureMemory", "/proc/pressure/memory", readPressure("memory"))
	SysDevicesSystemCpuOnline_Handler = newReadOnlyResource("SysDevicesSystemCpuOnline", "/sys/devices/system/cpu/online", readCPUOnline)
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

	data, err := h.read(req)
	if err != nil {
		return 0, err
	}

	if req.Offset >= int64(len(data)) {
		return 0, io.EOF
	}

	copied := copy(req.Data, data[req.Offset:])
	return copied, nil
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
	pid := req.Pid
	if req.Container != nil && req.Container.InitPid() != 0 {
		pid = req.Container.InitPid()
	}
	if pid == 0 {
		pid = uint32(os.Getpid())
	}

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
	return []byte{}, nil
}

func readSlabinfo(req *domain.HandlerRequest) ([]byte, error) {
	return []byte("slabinfo - version: 2.1\n# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>\n"), nil
}

func readCPUOnline(req *domain.HandlerRequest) ([]byte, error) {
	cg := cgroupForReq(req)
	if cpus, ok := cg.readV2("cpuset.cpus.effective"); ok && cpus != "" {
		return []byte(cpus + "\n"), nil
	}
	if cpus, ok := cg.readV2("cpuset.cpus"); ok && cpus != "" {
		return []byte(cpus + "\n"), nil
	}
	if cpus, ok := cg.readV1("cpuset", "cpuset.cpus"); ok && cpus != "" {
		return []byte(cpus + "\n"), nil
	}
	return hostFile("/sys/devices/system/cpu/online")
}

func effectiveCPUCount(req *domain.HandlerRequest) int {
	cg := cgroupForReq(req)
	limit := 0
	if online, err := readCPUOnline(req); err == nil {
		limit = countCPURange(strings.TrimSpace(string(online)))
	}

	if max, ok := cg.readV2("cpu.max"); ok {
		if fields := strings.Fields(max); len(fields) >= 2 && fields[0] == "max" {
			max, _ = cg.readV2Effective("cpu.max", func(s string) bool {
				fields := strings.Fields(s)
				return len(fields) >= 2 && fields[0] != "max"
			})
		}
		fields := strings.Fields(max)
		if len(fields) >= 2 && fields[0] != "max" {
			quota, qerr := strconv.ParseFloat(fields[0], 64)
			period, perr := strconv.ParseFloat(fields[1], 64)
			if qerr == nil && perr == nil && period > 0 {
				n := int(math.Ceil(quota / period))
				if n > 0 && (limit == 0 || n < limit) {
					limit = n
				}
			}
		}
	}

	if quotaStr, ok := cg.readV1("cpu", "cpu.cfs_quota_us"); ok {
		periodStr, _ := cg.readV1("cpu", "cpu.cfs_period_us")
		quota, qerr := strconv.ParseFloat(strings.TrimSpace(quotaStr), 64)
		period, perr := strconv.ParseFloat(strings.TrimSpace(periodStr), 64)
		if qerr == nil && perr == nil && quota > 0 && period > 0 {
			n := int(math.Ceil(quota / period))
			if n > 0 && (limit == 0 || n < limit) {
				limit = n
			}
		}
	}

	if limit <= 0 {
		return hostCPUCount()
	}
	return limit
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
	limit := effectiveCPUCount(req)
	blocks := bytes.Split(bytes.TrimSpace(data), []byte("\n\n"))
	if limit <= 0 || limit >= len(blocks) {
		return data, nil
	}

	out := bytes.Buffer{}
	for i := 0; i < limit; i++ {
		if i > 0 {
			out.WriteString("\n\n")
		}
		lines := bytes.Split(blocks[i], []byte("\n"))
		for j, line := range lines {
			if bytes.HasPrefix(line, []byte("processor")) {
				lines[j] = []byte(fmt.Sprintf("processor\t: %d", i))
			}
		}
		out.Write(bytes.Join(lines, []byte("\n")))
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
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
	fieldCount := 10
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				fieldCount = len(fields) - 1
			}
			break
		}
	}

	out := bytes.Buffer{}
	totals := procStatCPUTicks(req, limit, fieldCount, time.Now())
	writeProcStatCPULine(&out, "cpu", totals)
	for i := 0; i < limit; i++ {
		writeProcStatCPULine(&out, fmt.Sprintf("cpu%d", i), splitProcStatCPUTicks(totals, limit, i))
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
	out := bytes.Buffer{}
	writeMemLine(&out, "MemTotal", totalKB)
	writeMemLine(&out, "MemFree", availKB)
	writeMemLine(&out, "MemAvailable", availKB)
	writeMemLine(&out, "Buffers", 0)
	writeMemLine(&out, "Cached", minHost(host, "Cached", availKB))
	writeMemLine(&out, "SwapCached", 0)
	writeMemLine(&out, "Active", minHost(host, "Active", usedKB))
	writeMemLine(&out, "Inactive", minHost(host, "Inactive", usedKB))
	writeMemLine(&out, "Active(anon)", minHost(host, "Active(anon)", usedKB))
	writeMemLine(&out, "Inactive(anon)", minHost(host, "Inactive(anon)", usedKB))
	writeMemLine(&out, "Active(file)", minHost(host, "Active(file)", availKB))
	writeMemLine(&out, "Inactive(file)", minHost(host, "Inactive(file)", availKB))
	writeMemLine(&out, "Unevictable", minHost(host, "Unevictable", usedKB))
	writeMemLine(&out, "Mlocked", minHost(host, "Mlocked", usedKB))
	writeMemLine(&out, "SwapTotal", swapTotal/1024)
	writeMemLine(&out, "SwapFree", swapFree/1024)
	writeMemLine(&out, "Dirty", minHost(host, "Dirty", usedKB))
	writeMemLine(&out, "Writeback", minHost(host, "Writeback", usedKB))
	writeMemLine(&out, "AnonPages", minHost(host, "AnonPages", usedKB))
	writeMemLine(&out, "Mapped", minHost(host, "Mapped", usedKB))
	writeMemLine(&out, "Shmem", minHost(host, "Shmem", usedKB))
	writeMemLine(&out, "KReclaimable", minHost(host, "KReclaimable", usedKB))
	writeMemLine(&out, "Slab", minHost(host, "Slab", usedKB))
	writeMemLine(&out, "SReclaimable", minHost(host, "SReclaimable", usedKB))
	writeMemLine(&out, "SUnreclaim", minHost(host, "SUnreclaim", usedKB))
	return out.Bytes(), nil
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

func (c cgroupView) readV2MemoryUsage() (string, bool) {
	return readV2MemoryUsageFrom("/sys/fs/cgroup", c.v2Path)
}

func readV2MemoryUsageFrom(base, v2Path string) (string, bool) {
	if v2Path == "" {
		return "", false
	}

	fallback, fallbackOk := readFirstExisting(filepath.Join(base, v2Path, "memory.current"))
	cgPath := filepath.Clean(v2Path)
	for {
		max, ok := readFirstExisting(filepath.Join(base, cgPath, "memory.max"))
		if ok && max != "" && max != "max" {
			if usage, usageOk := readFirstExisting(filepath.Join(base, cgPath, "memory.current")); usageOk {
				return usage, true
			}
		}
		if cgPath == "." || cgPath == "/" {
			break
		}
		cgPath = filepath.Dir(cgPath)
	}

	return fallback, fallbackOk
}

func parseUintValueFromV1(cg cgroupView, ctrl, name string) (uint64, bool) {
	if v, ok := cg.readV1(ctrl, name); ok {
		return parseUintValue(v)
	}
	return 0, false
}

func swapValues(cg cgroupView) (uint64, uint64) {
	if max, ok := cg.readV2("memory.swap.max"); ok {
		total, hasTotal := parseUintValue(max)
		if !hasTotal {
			return 0, 0
		}
		current, _ := parseUintValueFromV2(cg, "memory.swap.current")
		return total, current
	}

	memLimit, hasMemLimit := memoryLimit(cg)
	memswLimit, hasMemswLimit := parseUintValueFromV1(cg, "memory", "memory.memsw.limit_in_bytes")
	memUsage, _ := memoryUsage(cg)
	memswUsage, _ := parseUintValueFromV1(cg, "memory", "memory.memsw.usage_in_bytes")
	if hasMemLimit && hasMemswLimit && memswLimit > memLimit {
		used := uint64(0)
		if memswUsage > memUsage {
			used = memswUsage - memUsage
		}
		return memswLimit - memLimit, used
	}
	return 0, 0
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

func readPressure(name string) resourceReader {
	return func(req *domain.HandlerRequest) ([]byte, error) {
		cg := cgroupForReq(req)
		if data, ok := cg.readV2(filepath.Join(name + ".pressure")); ok {
			return []byte(data + "\n"), nil
		}
		return hostFile(filepath.Join("/proc/pressure", name))
	}
}
