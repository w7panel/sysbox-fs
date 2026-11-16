package recovery

import (
	"bytes"
	"github.com/cilium/ebpf"
	"os"
	"testing"
)

func TestFaultProgramSpec(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(faultProgram))
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Programs) != 4 || spec.Maps["events"].Type != ebpf.RingBuf {
		t.Fatal("incomplete detector")
	}
}
func TestFaultProgramLoads(t *testing.T) {
	if os.Getenv("SYSBOX_RECOVERY_PRIVILEGED") != "1" {
		t.Skip("requires kernel BTF, BPF and kprobe privileges")
	}
	events, err := NewEvents(nil)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer events.Close()
}
