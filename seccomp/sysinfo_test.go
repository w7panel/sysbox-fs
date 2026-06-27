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
	"time"
)

func TestSysinfoVirtualizationCache(t *testing.T) {
	sysinfoVirtualizationCacheReset()

	if _, ok := sysinfoVirtualizationCacheGet(1234, 5678); ok {
		t.Fatal("unexpected cache hit before value is stored")
	}

	sysinfoVirtualizationCachePut(1234, 5678, true)

	got, ok := sysinfoVirtualizationCacheGet(1234, 5678)
	if !ok {
		t.Fatal("expected cache hit after value is stored")
	}
	if !got {
		t.Fatal("cached sysinfo virtualization decision = false, want true")
	}

	if _, ok := sysinfoVirtualizationCacheGet(1234, 5679); ok {
		t.Fatal("unexpected cache hit for same pid with different start time")
	}
}

func TestSysinfoVirtualizationCachePrunesExpiredEntries(t *testing.T) {
	sysinfoVirtualizationCacheReset()

	sysinfoVirtualizationCache.entries[sysinfoVirtualizationCacheKey{pid: 1234, startTime: 5678}] = sysinfoVirtualizationCacheEntry{
		virtualized: true,
		expiresAt:   time.Now().Add(-time.Second),
	}

	sysinfoVirtualizationCachePut(2234, 6678, false)

	if _, ok := sysinfoVirtualizationCache.entries[sysinfoVirtualizationCacheKey{pid: 1234, startTime: 5678}]; ok {
		t.Fatal("expired cache entry was not pruned")
	}
}
