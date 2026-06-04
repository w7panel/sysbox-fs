//
// Copyright 2019-2023 Nestybox, Inc.
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
	"sync"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

type readOnlyDir struct {
	domain.HandlerBase
}

var ProcPressure_Handler = &readOnlyDir{
	domain.HandlerBase{
		Name:    "ProcPressure",
		Path:    "/proc/pressure",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			".": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0555)),
				Enabled: true,
			},
			"io": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0444)),
				Size:    4096,
				Enabled: true,
			},
			"cpu": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0444)),
				Size:    4096,
				Enabled: true,
			},
			"memory": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0444)),
				Size:    4096,
				Enabled: true,
			},
		},
	},
}

func (h *readOnlyDir) Lookup(n domain.IOnodeIface, req *domain.HandlerRequest) (os.FileInfo, error) {
	relpath, err := filepath.Rel(h.Path, n.Path())
	if err != nil {
		return nil, err
	}

	resource := relpath
	if resource == "." {
		resource = filepath.Base(h.Path)
	}

	v, ok := h.EmuResourceMap[relpath]
	if !ok {
		return h.Service.GetPassThroughHandler().Lookup(n, req)
	}

	return &domain.FileInfo{
		Fname:    resource,
		Fmode:    v.Mode,
		FmodTime: time.Now(),
		Fsize:    v.Size,
		FisDir:   v.Kind == domain.DirEmuResource,
	}, nil
}

func (h *readOnlyDir) Open(n domain.IOnodeIface, req *domain.HandlerRequest) (bool, error) {
	return false, nil
}

func (h *readOnlyDir) Read(n domain.IOnodeIface, req *domain.HandlerRequest) (int, error) {
	return 0, nil
}

func (h *readOnlyDir) Write(n domain.IOnodeIface, req *domain.HandlerRequest) (int, error) {
	return 0, nil
}

func (h *readOnlyDir) ReadDirAll(n domain.IOnodeIface, req *domain.HandlerRequest) ([]os.FileInfo, error) {
	entries := []os.FileInfo{}
	for name, resource := range h.EmuResourceMap {
		if name == "." || !resource.Enabled {
			continue
		}
		entries = append(entries, &domain.FileInfo{
			Fname:    name,
			Fmode:    resource.Mode,
			FmodTime: time.Now(),
			Fsize:    resource.Size,
			FisDir:   resource.Kind == domain.DirEmuResource,
		})
	}
	return entries, nil
}

func (h *readOnlyDir) ReadLink(n domain.IOnodeIface, req *domain.HandlerRequest) (string, error) {
	return "", nil
}

func (h *readOnlyDir) GetName() string {
	return h.Name
}

func (h *readOnlyDir) GetPath() string {
	return h.Path
}

func (h *readOnlyDir) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *readOnlyDir) GetEnabled() bool {
	return h.Enabled
}

func (h *readOnlyDir) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *readOnlyDir) GetResourcesList() []string {
	return []string{h.GetPath()}
}

func (h *readOnlyDir) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}
	return &resource.Mutex
}

func (h *readOnlyDir) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
