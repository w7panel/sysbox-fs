package state

import (
	"fmt"
	"os"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-runc/libcontainer/system"
)

func TestValidateResourceIdentity(t *testing.T) {
	pid := uint32(os.Getpid())
	stat, err := system.Stat(int(pid))
	if err != nil {
		t.Fatal(err)
	}
	ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		identity domain.ResourceIdentity
		fail     bool
	}{
		{"legacy", domain.ResourceIdentity{}, false},
		{"current", domain.ResourceIdentity{Pidns: ns, InitStartTime: stat.StartTime}, false},
		{"reused-pid", domain.ResourceIdentity{InitStartTime: stat.StartTime + 1}, true},
		{"changed-namespace", domain.ResourceIdentity{Pidns: "pid:[invalid]"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateResourceIdentity(pid, tc.identity); (err != nil) != tc.fail {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}
