package implementations

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/sysio"
)

func TestProcSysKernelThreadsMaxReadWithoutNSenter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "threads-max")
	content := []byte("1539254\n")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	n := sysio.NewIOService(domain.IOOsFileService).NewIOnode("threads-max", path, 0644)
	n.SetOpenFlags(syscall.O_RDONLY)
	h := &ProcSysKernel{}
	if _, err := h.Open(n, &domain.HandlerRequest{}); err != nil {
		t.Fatalf("read-only open: %v", err)
	}

	for _, tc := range []struct {
		offset int64
		want   string
	}{
		{0, "1539254\n"},
		{2, "39254\n"},
		{int64(len(content)), ""},
	} {
		req := &domain.HandlerRequest{Offset: tc.offset, Data: make([]byte, 32)}
		got, err := h.Read(n, req)
		if err != nil && err != io.EOF {
			t.Fatalf("read at offset %d: %v", tc.offset, err)
		}
		if string(req.Data[:got]) != tc.want {
			t.Fatalf("read at offset %d = %q, want %q", tc.offset, req.Data[:got], tc.want)
		}
	}

	if err := os.WriteFile(path, []byte("42\n"), 0644); err != nil {
		t.Fatal(err)
	}
	req := &domain.HandlerRequest{Data: make([]byte, 32)}
	got, err := h.Read(n, req)
	if err != nil && err != io.EOF {
		t.Fatalf("read updated value: %v", err)
	}
	if string(req.Data[:got]) != "42\n" {
		t.Fatalf("read updated value = %q, want %q", req.Data[:got], "42\n")
	}
}
