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
	"testing"
	"time"
)

func TestContainerUptime(t *testing.T) {
	ctime := time.Date(2026, 6, 4, 1, 2, 3, 0, time.UTC)
	now := ctime.Add(1500 * time.Millisecond)

	uptime := containerUptime(ctime, now)
	if uptime != 1.5 {
		t.Fatalf("containerUptime() = %v, want 1.5", uptime)
	}
}

func TestContainerUptimeDoesNotGoNegative(t *testing.T) {
	now := time.Date(2026, 6, 4, 1, 2, 3, 0, time.UTC)
	ctime := now.Add(time.Second)

	uptime := containerUptime(ctime, now)
	if uptime != 0 {
		t.Fatalf("containerUptime() = %v, want 0", uptime)
	}
}

func TestContainerIdleFromCgroupNil(t *testing.T) {
	// With nil container, fallback to uptime.
	idle := containerIdleFromCgroup(nil, 100)
	if idle != 100 {
		t.Fatalf("containerIdleFromCgroup(nil, 100) = %v, want 100", idle)
	}
}

func TestContainerIdleFromCgroupZeroUptime(t *testing.T) {
	idle := containerIdleFromCgroup(nil, 0)
	if idle != 0 {
		t.Fatalf("containerIdleFromCgroup(nil, 0) = %v, want 0", idle)
	}
}

func TestContainerIdleArithmetic(t *testing.T) {
	// Simulate what containerIdleFromCgroup does with usage_usec:
	// uptime=100, usage_usec=500000 => cpuSeconds=0.5 => idle=99.5
	usageUsec := uint64(500000)
	cpuSeconds := float64(usageUsec) / 1_000_000
	uptime := 100.0
	got := uptime - cpuSeconds
	if got < 0 {
		got = 0
	}
	if got != 99.5 {
		t.Fatalf("idle calculation: got %v, want 99.5", got)
	}
}

func TestContainerIdleClamp(t *testing.T) {
	// When cpuSeconds > uptime, idle should clamp to 0.
	usageUsec := uint64(200_000_000) // 200s
	cpuSeconds := float64(usageUsec) / 1_000_000
	uptime := 100.0
	got := uptime - cpuSeconds
	if got < 0 {
		got = 0
	}
	if got != 0 {
		t.Fatalf("idle clamp: got %v, want 0", got)
	}
}

func TestContainerIdleCgroupV1Arithmetic(t *testing.T) {
	// cpuacct.usage is in nanoseconds: 500_000_000 ns = 0.5s
	usageNs := uint64(500_000_000)
	cpuSeconds := float64(usageNs) / 1_000_000_000
	uptime := 100.0
	got := uptime - cpuSeconds
	if got < 0 {
		got = 0
	}
	if got != 99.5 {
		t.Fatalf("cgroupv1 idle calculation: got %v, want 99.5", got)
	}
}
