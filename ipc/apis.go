//
// Copyright 2019-2020 Nestybox, Inc.
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

package ipc

import (
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/nestybox/sysbox-fs/domain"
	grpc "github.com/nestybox/sysbox-ipc/sysboxFsGrpc"
	ipcLib "github.com/nestybox/sysbox-ipc/sysboxMgrLib"
	grpcCodes "google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

type ipcService struct {
	grpcServer *grpc.Server
	css        domain.ContainerStateServiceIface
	prs        domain.ProcessServiceIface
	ios        domain.IOServiceIface
}

func NewIpcService() domain.IpcServiceIface {
	return &ipcService{}
}

func (ips *ipcService) Setup(
	css domain.ContainerStateServiceIface,
	prs domain.ProcessServiceIface,
	ios domain.IOServiceIface,
	fuseMp string) {

	ips.css = css
	ips.prs = prs
	ips.ios = ios

	// Instantiate a grpcServer for inter-process communication.
	ips.grpcServer = grpc.NewServer(
		ips,
		&grpc.CallbacksMap{
			grpc.ContainerPreRegisterMessage: ContainerPreRegister,
			grpc.ContainerRegisterMessage:    ContainerRegister,
			grpc.ContainerUnregisterMessage:  ContainerUnregister,
			grpc.ContainerUpdateMessage:      ContainerUpdate,
		},
		fuseMp,
	)

	logrus.Infof("Listening on %v", ips.grpcServer.GetAddr())
}

func (ips *ipcService) Init() error {
	return ips.grpcServer.Init()
}

func ContainerPreRegister(ctx interface{}, data *grpc.ContainerData) error {
	mode := ipcLib.MappingMode(data.MappingMode)
	if !mode.Valid() {
		return grpcStatus.Error(grpcCodes.InvalidArgument, "invalid mapping mode")
	}

	ipcService := ctx.(*ipcService)

	err := ipcService.css.ContainerPreRegister(data.Id, preRegisterNetnsPath(data.Netns, mode))
	if err != nil {
		return err
	}

	return nil
}

// preRegisterNetnsPath resolves the transient CRI netns handle through the L1
// init process when sysbox-fs runs in a hostPID agent with its own mount
// namespace. Do not broaden this to arbitrary paths: only the CNI-managed
// directory is part of the nested runtime contract.
func preRegisterNetnsPath(netns string, mode ipcLib.MappingMode) string {
	if netns == "" || mode != ipcLib.NestedIdentity {
		return netns
	}

	clean := filepath.Clean(netns)
	dir := filepath.Dir(clean)
	if dir != "/run/netns" && dir != "/var/run/netns" {
		return netns
	}

	return "/proc/1/root" + clean
}

func ContainerRegister(ctx interface{}, data *grpc.ContainerData) error {
	mode := ipcLib.MappingMode(data.MappingMode)
	if !mode.Valid() {
		return grpcStatus.Error(grpcCodes.InvalidArgument, "invalid mapping mode")
	}
	if mode == ipcLib.NestedIdentity {
		if data.UidFirst != 0 || data.GidFirst != 0 || data.UidSize != 65536 || data.GidSize != 65536 {
			return grpcStatus.Error(grpcCodes.InvalidArgument, "nested-identity requires uid/gid mapping 0:0:65536")
		}
	} else if data.UidFirst == 0 || data.GidFirst == 0 {
		return grpcStatus.Error(grpcCodes.InvalidArgument, "standard-subid does not allow uid/gid 0")
	}

	ipcService := ctx.(*ipcService)

	// Create temporary container struct to be passed as reference to containerDB,
	// where the matching (real) container will be identified and then updated.
	cntr := ipcService.css.ContainerCreate(
		data.Id,
		uint32(data.InitPid),
		data.Ctime,
		uint32(data.UidFirst),
		uint32(data.UidSize),
		uint32(data.GidFirst),
		uint32(data.GidSize),
		data.ProcRoPaths,
		data.ProcMaskPaths,
		ipcService.css,
	)
	if cntr != nil {
		cntr.SetMappingMode(data.MappingMode)
	}

	err := ipcService.css.ContainerRegister(cntr)
	if err != nil {
		return err
	}

	return nil
}

func ContainerUnregister(ctx interface{}, data *grpc.ContainerData) error {

	ipcService := ctx.(*ipcService)

	// Identify the container being unregistered.
	cntr := ipcService.css.ContainerLookupById(data.Id)
	if cntr == nil {
		return grpcStatus.Errorf(
			grpcCodes.NotFound,
			"Container %s not found",
			data.Id,
		)
	}

	err := ipcService.css.ContainerUnregister(cntr)
	if err != nil {
		return err
	}

	return nil
}

func ContainerUpdate(ctx interface{}, data *grpc.ContainerData) error {

	ipcService := ctx.(*ipcService)

	// Create temporary container struct to be passed as reference to containerDB,
	// where the matching (real) container will be identified and then updated.
	cntr := ipcService.css.ContainerCreate(
		data.Id,
		uint32(data.InitPid),
		data.Ctime,
		uint32(data.UidFirst),
		uint32(data.UidSize),
		uint32(data.GidFirst),
		uint32(data.GidSize),
		nil,
		nil,
		ipcService.css,
	)
	if cntr != nil {
		cntr.SetMappingMode(data.MappingMode)
	}

	err := ipcService.css.ContainerUpdate(cntr)
	if err != nil {
		return err
	}

	return nil
}
