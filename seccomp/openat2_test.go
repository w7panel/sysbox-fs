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
	"os"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/process"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

type openat2ProcessProbe struct {
	domain.ProcessIface
	fdPath string
}

func (p openat2ProcessProbe) GetFd(int32) (string, error)                 { return p.fdPath, nil }
func (p openat2ProcessProbe) ResolveProcSelf(path string) (string, error) { return path, nil }

func TestRelativeOpenat2OutsideSysboxfsSkipsProcessAttrs(t *testing.T) {
	si := &openat2SyscallInfo{
		syscallCtx: syscallCtx{
			reqId:       42,
			tracer:      &syscallTracer{},
			processInfo: openat2ProcessProbe{fdPath: "/sys/fs/cgroup"},
		},
		dirfd: 3,
		path:  "memory.current",
	}
	resp, err := si.processOpenat2()
	if err != nil || resp.ID != 42 || resp.Flags != libseccomp.NotifRespFlagContinue {
		t.Fatalf("relative non-managed openat2: resp=%+v, err=%v", resp, err)
	}
}

func BenchmarkRelativeOpenat2OutsideSysboxfs(b *testing.B) {
	fd, err := os.Open("/sys/fs/cgroup")
	if err != nil {
		b.Fatal(err)
	}
	defer fd.Close()
	prs := process.NewProcessService()
	tracer := &syscallTracer{}
	pid := uint32(os.Getpid())
	for _, eager := range []bool{true, false} {
		name := "lazy"
		if eager {
			name = "eager"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				p := prs.ProcessCreate(pid, 0, 0)
				si := openat2SyscallInfo{
					syscallCtx: syscallCtx{pid: pid, tracer: tracer, processInfo: p},
					dirfd:      int32(fd.Fd()),
					path:       "memory.current",
				}
				if eager {
					si.uid, si.gid, si.cwd, si.root, si.caps = p.Uid(), p.Gid(), p.Cwd(), p.Root(), p.GetEffCaps()
				}
				if _, err := si.processOpenat2(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

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
