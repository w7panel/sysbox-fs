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

import "testing"

func TestSysinfoVirtualizationCache(t *testing.T) {
	sysinfoVirtualizationCacheReset()

	if _, ok := sysinfoVirtualizationCacheGet(1234); ok {
		t.Fatal("unexpected cache hit before value is stored")
	}

	sysinfoVirtualizationCachePut(1234, true)

	got, ok := sysinfoVirtualizationCacheGet(1234)
	if !ok {
		t.Fatal("expected cache hit after value is stored")
	}
	if !got {
		t.Fatal("cached sysinfo virtualization decision = false, want true")
	}
}
