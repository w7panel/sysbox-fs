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

package mount

import "testing"

func TestIsSysboxfsMount(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/proc/meminfo", true},
		{"/proc/sys/kernel/threads-max", true},
		{"/sys/devices/virtual/net", true},
		{"/proc/meminfo-extra", false},
		{"/sys/devices/virtuality", false},
		{"/etc/hosts", false},
	}
	for _, test := range tests {
		if got := IsSysboxfsMount(test.path); got != test.want {
			t.Errorf("IsSysboxfsMount(%q) = %t, want %t", test.path, got, test.want)
		}
	}
}
