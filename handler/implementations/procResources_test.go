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
