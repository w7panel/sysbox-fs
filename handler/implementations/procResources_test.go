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

package implementations

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadV2MemoryUsageUsesEffectiveLimitCgroup(t *testing.T) {
	base := t.TempDir()
	containerPath := "kubepods/burstable/pod123/container456"
	initScopePath := filepath.Join(containerPath, "init.scope")

	writeCgroupFile(t, base, containerPath, "memory.max", "536870912\n")
	writeCgroupFile(t, base, containerPath, "memory.current", "73400320\n")
	writeCgroupFile(t, base, initScopePath, "memory.max", "max\n")
	writeCgroupFile(t, base, initScopePath, "memory.current", "102400\n")

	usage, ok := readV2MemoryUsageFrom(base, initScopePath)
	if !ok {
		t.Fatal("readV2MemoryUsageFrom() ok = false, want true")
	}
	if usage != "73400320" {
		t.Fatalf("readV2MemoryUsageFrom() = %q, want 73400320", usage)
	}
}

func TestReadV2MemoryStatUsesEffectiveLimitCgroup(t *testing.T) {
	base := t.TempDir()
	containerPath := "kubepods/burstable/pod123/container456"
	initScopePath := filepath.Join(containerPath, "init.scope")

	writeCgroupFile(t, base, containerPath, "memory.max", "536870912\n")
	writeCgroupFile(t, base, containerPath, "memory.stat", "anon 104857600\nfile 4096\n")
	writeCgroupFile(t, base, initScopePath, "memory.max", "max\n")
	writeCgroupFile(t, base, initScopePath, "memory.stat", "anon 40960\nfile 0\n")

	stat, ok := readV2MemoryStatFrom(base, initScopePath)
	if !ok {
		t.Fatal("readV2MemoryStatFrom() ok = false, want true")
	}
	if stat != "anon 104857600\nfile 4096" {
		t.Fatalf("readV2MemoryStatFrom() = %q, want parent memory.stat", stat)
	}
}

func TestReadV2MemoryUsageFallsBackToLeafCgroup(t *testing.T) {
	base := t.TempDir()
	cgPath := "kubepods/besteffort/pod123/container456"
	writeCgroupFile(t, base, cgPath, "memory.current", "102400\n")

	usage, ok := readV2MemoryUsageFrom(base, cgPath)
	if !ok {
		t.Fatal("readV2MemoryUsageFrom() ok = false, want true")
	}
	if usage != "102400" {
		t.Fatalf("readV2MemoryUsageFrom() = %q, want 102400", usage)
	}
}

func TestReadV2MemoryStatFallsBackToLeafCgroup(t *testing.T) {
	base := t.TempDir()
	cgPath := "kubepods/besteffort/pod123/container456"
	writeCgroupFile(t, base, cgPath, "memory.stat", "anon 102400\n")

	stat, ok := readV2MemoryStatFrom(base, cgPath)
	if !ok {
		t.Fatal("readV2MemoryStatFrom() ok = false, want true")
	}
	if stat != "anon 102400" {
		t.Fatalf("readV2MemoryStatFrom() = %q, want leaf memory.stat", stat)
	}
}

func writeCgroupFile(t *testing.T, base, cgPath, name, data string) {
	t.Helper()

	dir := filepath.Join(base, cgPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestProcStatCPUTicksUsesContainerTimeBase(t *testing.T) {
	ticks := procStatCPUTicksFromUsage(100, 4, 10, containerCPUUsage{
		UsageSeconds:  20,
		UserSeconds:   12,
		SystemSeconds: 8,
	})

	if ticks[0] != 1200 {
		t.Fatalf("user ticks = %d, want 1200", ticks[0])
	}
	if ticks[2] != 800 {
		t.Fatalf("system ticks = %d, want 800", ticks[2])
	}
	if ticks[3] != 38000 {
		t.Fatalf("idle ticks = %d, want 38000", ticks[3])
	}
}

func TestProcStatCPUTicksClampsUsageToCapacity(t *testing.T) {
	ticks := procStatCPUTicksFromUsage(100, 1, 10, containerCPUUsage{
		UsageSeconds:  200,
		UserSeconds:   120,
		SystemSeconds: 80,
	})

	if ticks[0]+ticks[2] != 10000 {
		t.Fatalf("used ticks = %d, want 10000", ticks[0]+ticks[2])
	}
	if ticks[3] != 0 {
		t.Fatalf("idle ticks = %d, want 0", ticks[3])
	}
}

func TestSplitProcStatCPUTicksPreservesTotals(t *testing.T) {
	total := []uint64{10, 0, 5, 7}
	sum := make([]uint64, len(total))

	for i := 0; i < 4; i++ {
		part := splitProcStatCPUTicks(total, 4, i)
		for j, v := range part {
			sum[j] += v
		}
	}

	for i, want := range total {
		if sum[i] != want {
			t.Fatalf("split total[%d] = %d, want %d", i, sum[i], want)
		}
	}
}

func TestSplitProcStatDeltaPreservesTotals(t *testing.T) {
	parts := splitProcStatDelta(procStatDelta{user: 11, system: 7, idle: 13}, []uint64{3, 1})

	sum := procStatDelta{}
	for _, part := range parts {
		sum.user += part.user
		sum.system += part.system
		sum.idle += part.idle
	}

	if sum.user != 11 || sum.system != 7 || sum.idle != 13 {
		t.Fatalf("splitProcStatDelta() totals = %+v, want user=11 system=7 idle=13", sum)
	}
}

func TestProcStatUsageDeltaClampsToElapsedCapacity(t *testing.T) {
	delta := procStatUsageDelta(
		containerCPUUsage{UsageSeconds: 20, UserSeconds: 15, SystemSeconds: 5},
		containerCPUUsage{},
		1,
		2,
	)

	if got := delta.user + delta.system + delta.idle; got != 200 {
		t.Fatalf("total delta ticks = %d, want 200", got)
	}
	if delta.idle != 0 {
		t.Fatalf("idle delta ticks = %d, want 0", delta.idle)
	}
}

func TestParseProcStatHostCPUs(t *testing.T) {
	fieldCount, cpus := parseProcStatHostCPUs([]string{
		"cpu  10 0 5 20 1 2 3 0 0 0",
		"cpu0 4 0 2 10 0 0 0 0 0 0",
		"cpu1 6 0 3 10 1 2 3 0 0 0",
		"intr 1",
	})

	if fieldCount != 10 {
		t.Fatalf("fieldCount = %d, want 10", fieldCount)
	}
	if len(cpus) != 2 {
		t.Fatalf("cpus len = %d, want 2", len(cpus))
	}
	if got := procStatBusyDelta(cpus[1], cpus[0]); got != 9 {
		t.Fatalf("procStatBusyDelta() = %d, want 9", got)
	}
}

func TestWriteProcStatCPULine(t *testing.T) {
	out := bytes.Buffer{}
	writeProcStatCPULine(&out, "cpu0", []uint64{1, 2, 3, 4})

	if got, want := out.String(), "cpu0 1 2 3 4\n"; got != want {
		t.Fatalf("writeProcStatCPULine() = %q, want %q", got, want)
	}
}

func TestCPURangeForCount(t *testing.T) {
	cases := []struct {
		count int
		want  string
	}{
		{0, "0"},
		{1, "0"},
		{4, "0-3"},
	}

	for _, tc := range cases {
		if got := cpuRangeForCount(tc.count); got != tc.want {
			t.Fatalf("cpuRangeForCount(%d) = %q, want %q", tc.count, got, tc.want)
		}
	}
}

func TestCPUInfoFromHostFiltersByCPUSetAndRenumbers(t *testing.T) {
	host := []byte(strings.Join([]string{
		"processor\t: 0\nmodel name\t: cpu0",
		"processor\t: 1\nmodel name\t: cpu1",
		"processor\t: 2\nmodel name\t: cpu2",
		"processor\t: 3\nmodel name\t: cpu3",
	}, "\n\n"))

	got := string(cpuInfoFromHost(host, "1,3", 0))
	want := "processor\t: 0\nmodel name\t: cpu1\n\nprocessor\t: 1\nmodel name\t: cpu3\n"
	if got != want {
		t.Fatalf("cpuInfoFromHost() = %q, want %q", got, want)
	}
}

func TestCPUInfoFromHostAppliesQuotaLimit(t *testing.T) {
	host := []byte(strings.Join([]string{
		"processor\t: 0\nmodel name\t: cpu0",
		"processor\t: 1\nmodel name\t: cpu1",
		"processor\t: 2\nmodel name\t: cpu2",
	}, "\n\n"))

	got := string(cpuInfoFromHost(host, "0-2", 2))
	want := "processor\t: 0\nmodel name\t: cpu0\n\nprocessor\t: 1\nmodel name\t: cpu1\n"
	if got != want {
		t.Fatalf("cpuInfoFromHost() = %q, want %q", got, want)
	}
}

func TestCPUInCPUSet(t *testing.T) {
	if !cpuInCPUSet(2, "0,2-3") {
		t.Fatal("cpuInCPUSet(2, \"0,2-3\") = false, want true")
	}
	if !cpuInCPUSet(2, "3-2") {
		t.Fatal("cpuInCPUSet(2, \"3-2\") = false, want true")
	}
	if cpuInCPUSet(4, "0,2-3") {
		t.Fatal("cpuInCPUSet(4, \"0,2-3\") = true, want false")
	}
}

func TestParseCPUQuota(t *testing.T) {
	if got, ok := parseCPUQuota("250000 100000"); !ok || got != 2.5 {
		t.Fatalf("parseCPUQuota() = %v, %v; want 2.5, true", got, ok)
	}
	if _, ok := parseCPUQuota("max 100000"); ok {
		t.Fatal("parseCPUQuota(max) ok = true, want false")
	}
}

func TestDiskstatsFromIOStat(t *testing.T) {
	stats := parseIOStatValues("8:0 rbytes=1024 wbytes=2048 rios=3 wios=4 dbytes=512 dios=1\n")
	got := string(diskstatsFromIOStatValues(stats, []diskDevice{{major: 8, minor: 0, name: "sda"}}))

	if !bytes.Contains([]byte(got), []byte("8")) ||
		!bytes.Contains([]byte(got), []byte("3 0 2 0")) ||
		!bytes.Contains([]byte(got), []byte("4 0 4 0")) {
		t.Fatalf("diskstatsFromIOStat() = %q, want converted io counters", got)
	}
}

func TestDiskstatsFromBlkIOStatsUsesDiskstatsOrder(t *testing.T) {
	stats := blkIOStats{
		serviced: map[string]map[string]uint64{
			"8:16": {"Read": 1},
			"8:0":  {"Write": 2},
		},
		serviceBytes: map[string]map[string]uint64{
			"8:16": {"Read": 1024},
			"8:0":  {"Write": 2048},
		},
	}

	got, ok := diskstatsFromBlkIOStats(stats, []diskDevice{
		{major: 8, minor: 0, name: "sda"},
		{major: 8, minor: 16, name: "sdb"},
	})
	if !ok {
		t.Fatal("diskstatsFromBlkIOStats() ok = false, want true")
	}
	lines := strings.Split(strings.TrimSpace(string(got)), "\n")
	if len(lines) != 2 {
		t.Fatalf("diskstatsFromBlkIOStats() line count = %d, want 2: %q", len(lines), got)
	}
	if !strings.Contains(lines[0], "8       0 sda") || !strings.Contains(lines[1], "8       16 sdb") {
		t.Fatalf("diskstatsFromBlkIOStats() = %q, want host diskstats order", got)
	}
}

func TestParseBlkIOValues(t *testing.T) {
	values := parseBlkIOValues("8:0 Read 10\n8:0 Write 20\nTotal 30\n")

	if values["8:0"]["Read"] != 10 {
		t.Fatalf("Read = %d, want 10", values["8:0"]["Read"])
	}
	if values["8:0"]["Write"] != 20 {
		t.Fatalf("Write = %d, want 20", values["8:0"]["Write"])
	}
	if _, ok := values["Total"]; ok {
		t.Fatal("parseBlkIOValues() kept aggregate Total line")
	}
}

func TestParseMemoryStatPrefersTotalValues(t *testing.T) {
	stat := parseMemoryStat("active_anon 1024\ntotal_active_anon 2048\nfile 4096\n", true)

	if got := stat.kb("active_anon"); got != 2 {
		t.Fatalf("active_anon = %dKB, want 2KB", got)
	}
	if got := stat.kb("file"); got != 4 {
		t.Fatalf("file = %dKB, want 4KB", got)
	}
}

func TestContainerProcStatsMissingRoot(t *testing.T) {
	total, running, lastPID, ok := containerProcStats(-1)
	if ok {
		t.Fatalf("containerProcStats(-1) = (%d, %d, %d, true), want ok=false", total, running, lastPID)
	}
}

func TestCalcLoadavg(t *testing.T) {
	got := calcLoadavg(0, loadavgExp1, 1)
	if got == 0 {
		t.Fatal("calcLoadavg() returned 0 for one active task")
	}
}

func TestNormalizeLoadavgSampleKeepsNonEmptyContainerActive(t *testing.T) {
	total, running := normalizeLoadavgSample(46, 0)
	if total != 46 || running != 1 {
		t.Fatalf("normalizeLoadavgSample(46, 0) = (%d, %d), want (46, 1)", total, running)
	}
}

func TestNormalizeLoadavgSampleExpandsTotalForRunningTasks(t *testing.T) {
	total, running := normalizeLoadavgSample(1, 8)
	if total != 8 || running != 8 {
		t.Fatalf("normalizeLoadavgSample(1, 8) = (%d, %d), want (8, 8)", total, running)
	}
}

func TestLoadavgNodeFormat(t *testing.T) {
	node := &loadavgNode{
		avenrun: [3]uint64{loadavgFixed1, loadavgFixed1 / 2, 0},
		running: 2,
		total:   5,
		lastPID: 9,
	}

	got := node.format()
	if got != "1.00 0.50 0.00 2/5 9\n" {
		t.Fatalf("loadavgNode.format() = %q", got)
	}
}

func TestLoadavgActiveStateIncludesUninterruptibleTasks(t *testing.T) {
	for _, state := range []string{"R", "D"} {
		if !loadavgActiveState(state) {
			t.Fatalf("loadavgActiveState(%q) = false, want true", state)
		}
	}
	if loadavgActiveState("S") {
		t.Fatal("loadavgActiveState(\"S\") = true, want false")
	}
}

func TestNamespacePIDFromStatusUsesInnermostNSpid(t *testing.T) {
	statusPath := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(statusPath, []byte("Name:\tt\nNSpid:\t100\t7\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if got := namespacePIDFromStatus(statusPath, 100); got != 7 {
		t.Fatalf("namespacePIDFromStatus() = %d, want 7", got)
	}
}

func TestPruneInitScopePath(t *testing.T) {
	tests := map[string]string{
		"/init.scope":                        "/",
		"/kubepods/pod/container/init.scope": "/kubepods/pod/container",
		"/kubepods/pod/container":            "/kubepods/pod/container",
	}
	for input, want := range tests {
		if got := pruneInitScopePath(input); got != want {
			t.Fatalf("pruneInitScopePath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBoundedSwapInfoCapsHostSwap(t *testing.T) {
	info := boundedSwapInfo(4096, 512, 1024, 1)
	if info.totalKB != 1024 {
		t.Fatalf("totalKB = %d, want host cap 1024", info.totalKB)
	}
	if info.usedKB != 512 {
		t.Fatalf("usedKB = %d, want 512", info.usedKB)
	}
}

func TestSwapInfoV2MaxDoesNotExposeHostSwap(t *testing.T) {
	if _, ok := swapInfoV2FromMax("max", 64*1024, 1024); ok {
		t.Fatal("swapInfoV2FromMax() ok = true for max, want false")
	}
}

func TestSwapInfoV1UsesMemswLimit(t *testing.T) {
	info, ok := swapInfoV1FromLimits(512*1024, 768*1024, 64, 1024, 1)
	if !ok {
		t.Fatal("swapInfoV1FromLimits() ok = false, want true")
	}
	if info.totalKB != 768 {
		t.Fatalf("totalKB = %d, want memsw limit 768", info.totalKB)
	}
	if info.usedKB != 64 {
		t.Fatalf("usedKB = %d, want 64", info.usedKB)
	}
}

func TestSwapInfoV1UnlimitedDoesNotExposeHostSwap(t *testing.T) {
	if _, ok := swapInfoV1FromLimits(512*1024, uint64(math.MaxInt64), 64, 1024, 1); ok {
		t.Fatal("swapInfoV1FromLimits() ok = true for unlimited memsw, want false")
	}
}

func TestBoundedSwapInfoSwappinessZero(t *testing.T) {
	info := boundedSwapInfo(4096, 512, 8192, 0)
	if info.totalKB != 512 {
		t.Fatalf("totalKB = %d, want usedKB when swappiness=0", info.totalKB)
	}
	if info.usedKB != 512 {
		t.Fatalf("usedKB = %d, want 512", info.usedKB)
	}
}

func TestBoundedSwapInfoClampsUsed(t *testing.T) {
	info := boundedSwapInfo(256, 512, 1024, 1)
	if info.usedKB != 256 {
		t.Fatalf("usedKB = %d, want clamped total 256", info.usedKB)
	}
}

func TestEnsureTrailingNewline(t *testing.T) {
	if got := ensureTrailingNewline("some avg10=0.00"); got != "some avg10=0.00\n" {
		t.Fatalf("ensureTrailingNewline() = %q", got)
	}
	if got := ensureTrailingNewline("x\n"); got != "x\n" {
		t.Fatalf("ensureTrailingNewline() changed newline-terminated data: %q", got)
	}
}
