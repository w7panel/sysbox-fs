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
	"os"
	"path/filepath"
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

func TestDiskstatsFromIOStat(t *testing.T) {
	got := string(diskstatsFromIOStat("8:0 rbytes=1024 wbytes=2048 rios=3 wios=4 dbytes=512 dios=1\n"))

	if !bytes.Contains([]byte(got), []byte("8")) ||
		!bytes.Contains([]byte(got), []byte("3 0 2 0")) ||
		!bytes.Contains([]byte(got), []byte("4 0 4 0")) {
		t.Fatalf("diskstatsFromIOStat() = %q, want converted io counters", got)
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

func TestBoundedSwapInfoCapsHostSwap(t *testing.T) {
	info := boundedSwapInfo(4096, 512, 1024, 1)
	if info.totalKB != 1024 {
		t.Fatalf("totalKB = %d, want host cap 1024", info.totalKB)
	}
	if info.usedKB != 512 {
		t.Fatalf("usedKB = %d, want 512", info.usedKB)
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
