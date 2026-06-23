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

package seccomp

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler/implementations"
	"golang.org/x/sys/unix"

	"github.com/sirupsen/logrus"
)

func (t *syscallTracer) processSysinfo(
	req *sysRequest,
	fd int32,
	cntr domain.ContainerIface) (*sysResponse, error) {

	addr := req.Data.Args[0]
	if addr == 0 {
		return t.createErrorResponse(req.ID, syscall.EFAULT), nil
	}
	if !shouldVirtualizeSysinfo(req.Pid) {
		return t.createContinueResponse(req.ID), nil
	}

	mem, ok := implementations.SysinfoMemoryForPid(req.Pid)
	if !ok {
		return t.createContinueResponse(req.ID), nil
	}

	info := unix.Sysinfo_t{}
	if err := unix.Sysinfo(&info); err != nil {
		return nil, err
	}

	info.Totalram = mem.TotalRAM
	info.Freeram = mem.FreeRAM
	info.Sharedram = mem.SharedRAM
	info.Bufferram = mem.BufferRAM
	info.Totalswap = mem.TotalSwap
	info.Freeswap = mem.FreeSwap
	info.Totalhigh = 0
	info.Freehigh = 0
	info.Unit = 1

	size := int(unsafe.Sizeof(info))
	data := make([]byte, size)
	copy(data, unsafe.Slice((*byte)(unsafe.Pointer(&info)), size))

	if err := t.memParser.WriteSyscallBytesArgs(req.Pid, []memParserDataElem{{
		addr: addr,
		size: size,
		data: data,
	}}); err != nil {
		return nil, err
	}

	logrus.Debugf("Handled sysinfo syscall from pid %d: totalram=%d freeram=%d totalswap=%d freeswap=%d",
		req.Pid, info.Totalram, info.Freeram, info.Totalswap, info.Freeswap)

	return t.createSuccessResponse(req.ID), nil
}

func shouldVirtualizeSysinfo(pid uint32) bool {
	exe, _ := processExe(pid)
	exeName := filepath.Base(exe)
	if exeName == "k3s" {
		return false
	}
	if exeName == "busybox" {
		return true
	}

	argv0, err := processArgv0(pid)
	if err == nil && filepath.Base(argv0) == "free" {
		return true
	}

	comm, err := processComm(pid)
	return err == nil && comm == "free"
}

func processArgv0(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", nil
	}

	arg0, _, _ := bytes.Cut(data, []byte{0})
	return string(arg0), nil
}

func processComm(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func processExe(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}
