package implementations

import (
	"os"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/sysio"
)

func TestProcSysFsBinfmtMountpoint(t *testing.T) {
	n := sysio.NewIOService(domain.IOOsFileService).NewIOnode("binfmt_misc", "/proc/sys/fs/binfmt_misc", 0)
	info, err := ProcSysFs_Handler.Lookup(n, &domain.HandlerRequest{})
	if err != nil || !info.IsDir() || info.Mode()&os.ModeDir == 0 {
		t.Fatalf("binfmt_misc mountpoint: info=%v err=%v", info, err)
	}
}
