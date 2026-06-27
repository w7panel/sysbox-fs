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
	libseccomp "github.com/seccomp/libseccomp-golang"
)

type countingMemParser struct {
	stringsRead int
	bytesRead   int
}

func (mp *countingMemParser) ReadSyscallStringArgs(pid uint32, elems []memParserDataElem) ([]string, error) {
	mp.stringsRead++
	return []string{"/tmp/file", "user.unhandled"}, nil
}

func (mp *countingMemParser) ReadSyscallBytesArgs(pid uint32, elems []memParserDataElem) ([]string, error) {
	mp.bytesRead++
	return []string{"ignored-value"}, nil
}

func (mp *countingMemParser) WriteSyscallBytesArgs(pid uint32, elems []memParserDataElem) error {
	return nil
}

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

func Test_syscallTracer_processSetxattr_skips_value_read_when_xattr_not_allowed(t *testing.T) {
	// Given
	memParser := &countingMemParser{}
	tracer := &syscallTracer{memParser: memParser}
	req := &sysRequest{
		ID:  42,
		Pid: 1001,
		Data: libseccomp.ScmpNotifData{
			Args: []uint64{1, 2, 3, 13, 0},
		},
	}

	// When
	resp, err := tracer.processSetxattr(req, 0, nil, "setxattr")

	// Then
	if err != nil {
		t.Fatalf("processSetxattr returned error: %v", err)
	}
	if resp == nil || resp.Flags != libseccomp.NotifRespFlagContinue {
		t.Fatalf("processSetxattr response = %#v, want continue response", resp)
	}
	if memParser.stringsRead != 1 {
		t.Fatalf("string args read count = %d, want 1", memParser.stringsRead)
	}
	if memParser.bytesRead != 0 {
		t.Fatalf("value read count = %d, want 0", memParser.bytesRead)
	}
}
