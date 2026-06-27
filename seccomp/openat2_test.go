//
// Copyright 2026 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package seccomp

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestCanEarlyContinueOpenat2(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		dirfd   int32
		resolve uint64
		want    bool
	}{
		{
			name:    "absolute cgroup path cannot hit sysboxfs mount",
			path:    "/sys/fs/cgroup/kubepods/burstable/pod123/memory.current",
			dirfd:   unix.AT_FDCWD,
			resolve: 0,
			want:    true,
		},
		{
			name:    "absolute non proc sys path cannot hit sysboxfs mount",
			path:    "/etc/hosts",
			dirfd:   unix.AT_FDCWD,
			resolve: 0,
			want:    true,
		},
		{
			name:    "managed proc mount requires full processing",
			path:    "/proc/meminfo",
			dirfd:   unix.AT_FDCWD,
			resolve: 0,
			want:    false,
		},
		{
			name:    "proc self fd path can continue through kernel",
			path:    "/proc/self/mountinfo",
			dirfd:   unix.AT_FDCWD,
			resolve: 0,
			want:    true,
		},
		{
			name:    "proc thread self fd path can continue through kernel",
			path:    "/proc/thread-self/fd",
			dirfd:   unix.AT_FDCWD,
			resolve: 0,
			want:    true,
		},
		{
			name:    "proc self root alias requires full processing",
			path:    "/proc/self/root/proc/meminfo",
			dirfd:   unix.AT_FDCWD,
			resolve: 0,
			want:    false,
		},
		{
			name:    "proc thread self root alias requires full processing",
			path:    "/proc/thread-self/root/sys/devices/system/cpu/online",
			dirfd:   unix.AT_FDCWD,
			resolve: 0,
			want:    false,
		},
		{
			name:    "managed sys mount requires full processing",
			path:    "/sys/devices/system/cpu/online",
			dirfd:   unix.AT_FDCWD,
			resolve: 0,
			want:    false,
		},
		{
			name:    "relative cgroup path requires dirfd resolution",
			path:    "kubepods/burstable/pod123/memory.current",
			dirfd:   12,
			resolve: 0,
			want:    false,
		},
		{
			name:    "resolve in root changes absolute path semantics",
			path:    "/sys/fs/cgroup/kubepods/burstable/pod123/memory.current",
			dirfd:   12,
			resolve: RESOLVE_IN_ROOT,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canEarlyContinueOpenat2(tt.path, tt.dirfd, tt.resolve)
			if got != tt.want {
				t.Fatalf("canEarlyContinueOpenat2(%q, %d, %#x) = %t, want %t",
					tt.path, tt.dirfd, tt.resolve, got, tt.want)
			}
		})
	}
}
