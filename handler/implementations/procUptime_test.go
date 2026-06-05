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
	"strings"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/state"
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
	got := containerIdleFromUsage(100, 1, 0.5)
	if got != 99.5 {
		t.Fatalf("containerIdleFromUsage() = %v, want 99.5", got)
	}
}

func TestContainerIdleUsesCPUCapacity(t *testing.T) {
	got := containerIdleFromUsage(100, 4, 20)
	if got != 380 {
		t.Fatalf("containerIdleFromUsage() = %v, want 380", got)
	}
}

func TestContainerIdleClamp(t *testing.T) {
	got := containerIdleFromUsage(100, 1, 200)
	if got != 0 {
		t.Fatalf("containerIdleFromUsage() = %v, want 0", got)
	}
}

func TestContainerIdleCgroupV1Arithmetic(t *testing.T) {
	got := containerIdleFromUsage(100, 1, 0.5)
	if got != 99.5 {
		t.Fatalf("containerIdleFromUsage() = %v, want 99.5", got)
	}
}

func TestProcUptimeNonZeroOffset(t *testing.T) {
	cntr := state.NewContainerStateService().ContainerCreate(
		"c1",
		0,
		time.Now().Add(-100*time.Second),
		231072,
		65535,
		231072,
		65535,
		nil,
		nil,
		nil)

	req := &domain.HandlerRequest{
		Offset:    1,
		Data:      make([]byte, 8),
		Container: cntr,
	}

	n, err := ProcUptime_Handler.readUptime(nil, req)
	if err != nil {
		t.Fatalf("readUptime() error = %v, want nil", err)
	}
	if n == 0 {
		t.Fatal("readUptime() returned 0 bytes at non-zero offset")
	}
	if strings.Contains(string(req.Data[:n]), "\x00") {
		t.Fatalf("readUptime() returned null bytes: %q", string(req.Data[:n]))
	}
}
