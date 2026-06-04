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

func TestParseProcUptime(t *testing.T) {
	uptime, idle, err := parseProcUptime("123.45 678.90\n")
	if err != nil {
		t.Fatalf("parseProcUptime() error = %v", err)
	}

	if uptime != 123.45 {
		t.Fatalf("parseProcUptime() uptime = %v, want 123.45", uptime)
	}

	if idle != 678.90 {
		t.Fatalf("parseProcUptime() idle = %v, want 678.90", idle)
	}
}

func TestParseProcUptimeInvalid(t *testing.T) {
	if _, _, err := parseProcUptime("123.45\n"); err == nil {
		t.Fatal("parseProcUptime() error = nil, want error")
	}

	if _, _, err := parseProcUptime("foo 678.90\n"); err == nil {
		t.Fatal("parseProcUptime() error = nil, want error")
	}
}

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

func TestContainerIdleApprox(t *testing.T) {
	idle := containerIdleApprox(10, 100, 250)
	if idle != 25 {
		t.Fatalf("containerIdleApprox() = %v, want 25", idle)
	}
}

func TestContainerIdleApproxFallback(t *testing.T) {
	idle := containerIdleApprox(10, 0, 250)
	if idle != 10 {
		t.Fatalf("containerIdleApprox() = %v, want 10", idle)
	}
}
