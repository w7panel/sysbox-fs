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

	"github.com/nestybox/sysbox-fs/domain"
)

func TestProcSwapsHeader(t *testing.T) {
	data := string(procSwapsData(nil))
	if data != swapsHeader+"\n" {
		t.Fatalf("procSwapsData(nil) = %q, want header only", data)
	}
}

func TestProcSwapsVirtualLineFormat(t *testing.T) {
	line := formatProcSwapsVirtualLine(swapInfo{totalKB: 1024, usedKB: 128})
	if !strings.HasPrefix(line, "none") || !strings.Contains(line, "virtual\t\t1024\t128\t0\n") {
		t.Fatalf("formatProcSwapsVirtualLine() = %q", line)
	}
}

func TestProcSwapsSplitReadKeepsSnapshot(t *testing.T) {
	h := &ProcSwaps{}
	owner := &domain.ResourceOwner{ID: 42}
	req := &domain.HandlerRequest{Pid: ^uint32(0), ResourceOwner: owner, Data: make([]byte, 12)}
	want := string(procSwapsData(req))
	n, err := h.readSwaps(nil, req)
	if err != nil || string(req.Data[:n]) != want[:12] {
		t.Fatalf("first read: %q, %v", req.Data[:n], err)
	}
	original := swapsHeader
	swapsHeader = "changed"
	defer func() { swapsHeader = original }()
	req.Offset = int64(n)
	req.Data = make([]byte, len(want))
	n, err = h.readSwaps(nil, req)
	if err != nil || string(req.Data[:n]) != want[12:] {
		t.Fatalf("continued read: %q, %v", req.Data[:n], err)
	}
	h.ReleaseResourceSnapshots(resourceOwnerKey(req))
	if len(h.snapshots.entries) != 0 {
		t.Fatal("swaps snapshot survived owner release")
	}
}
