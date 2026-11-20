package implementations

import (
	"os"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/sysio"
)

func TestProcSysFsBinfmtMountpoint(t *testing.T) {
	for _, name := range []string{"fs", "binfmt_misc"} {
		path := "/proc/sys/fs"
		if name == "binfmt_misc" {
			path += "/binfmt_misc"
		}
		n := sysio.NewIOService(domain.IOOsFileService).NewIOnode(name, path, 0)
		info, err := ProcSysFs_Handler.Lookup(n, &domain.HandlerRequest{})
		if err != nil || !info.IsDir() || info.Mode()&os.ModeDir == 0 {
			t.Fatalf("%s mountpoint: info=%v err=%v", name, info, err)
		}
		if name == "fs" && info.Mode().Perm() != 0555 {
			t.Fatalf("fs parent mode = %o, want 0555", info.Mode().Perm())
		}
	}
}
