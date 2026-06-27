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
	"errors"
	"fmt"
	"reflect"
	"syscall"
	"testing"

	unixIpc "github.com/nestybox/sysbox-ipc/unix"
)

func Test_syscallTracer_createErrorResponse(t *testing.T) {
	type fields struct {
		sms      *SyscallMonitorService
		srv      *unixIpc.Server
		pollsrv  *unixIpc.PollServer
		syscalls map[seccompArchSyscallPair]string
	}

	var f1 = &fields{
		sms:      nil,
		srv:      nil,
		pollsrv:  nil,
		syscalls: nil,
	}

	var r1 = &sysResponse{
		ID:    0,
		Error: int32(syscall.EPERM),
		Val:   0,
		Flags: 0,
	}
	var r2 = &sysResponse{
		ID:    1,
		Error: int32(syscall.EINVAL),
		Val:   0,
		Flags: 0,
	}

	type args struct {
		id  uint64
		err error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *sysResponse
	}{
		{"1", *f1, args{0, syscall.EPERM}, r1},
		{"2", *f1, args{1, fmt.Errorf("testing errorString error type 1")}, r2},
		{"3", *f1, args{1, errors.New("testing errorString error type 2")}, r2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer := &syscallTracer{
				service:  tt.fields.sms,
				srv:      tt.fields.srv,
				pollsrv:  tt.fields.pollsrv,
				syscalls: tt.fields.syscalls,
			}
			if got := tracer.createErrorResponse(tt.args.id, tt.args.err); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("syscallTracer.createErrorResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsStaleSeccompNotification(t *testing.T) {
	if !isStaleSeccompNotification(syscall.ENOENT) {
		t.Fatal("ENOENT notification error should be treated as stale")
	}

	if !isStaleSeccompNotification(errors.Join(errors.New("wrapped"), syscall.ENOENT)) {
		t.Fatal("wrapped ENOENT notification error should be treated as stale")
	}

	if isStaleSeccompNotification(syscall.EPERM) {
		t.Fatal("EPERM notification error should not be treated as stale")
	}
}
