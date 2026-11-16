package recovery

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Fault struct {
	Cgroup    uint64
	Namespace uint64
	PID       uint32
	Device    uint32
}

type Events struct {
	closeOnce  sync.Once
	collection *ebpf.Collection
	reader     *ringbuf.Reader
	links      []link.Link
}

func NewEvents(devices []uint32) (_ *Events, err error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(faultProgram))
	if err != nil {
		return nil, err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}
	var fn *btf.Func
	if err := kernel.TypeByName("fuse_get_req", &fn); err != nil {
		return nil, fmt.Errorf("FUSE recovery needs fuse_get_req BTF: %w", err)
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return nil, fmt.Errorf("invalid fuse_get_req prototype")
	}
	var argument uint32
	for i, param := range proto.Params {
		if param.Name == "fm" {
			argument = uint32(i + 1)
		}
	}
	if argument != 1 && argument != 2 {
		return nil, fmt.Errorf("unsupported fuse_get_req prototype")
	}
	if err := spec.RewriteConstants(map[string]interface{}{"fuse_mount_argument": argument}); err != nil {
		return nil, err
	}
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load FUSE fault detector: %w", err)
	}
	e := &Events{collection: c}
	defer func() {
		if err != nil {
			e.Close()
		}
	}()
	for _, dev := range devices {
		if err = c.Maps["allowed"].Put(dev, uint8(1)); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"read_enter", "read_exit", "request_enter", "request_exit"} {
		var hook link.Link
		switch name {
		case "read_enter":
			hook, err = link.Tracepoint("syscalls", "sys_enter_read", c.Programs[name], nil)
		case "read_exit":
			hook, err = link.Tracepoint("syscalls", "sys_exit_read", c.Programs[name], nil)
		case "request_enter":
			hook, err = link.Kprobe("fuse_get_req", c.Programs[name], nil)
		case "request_exit":
			hook, err = link.Kretprobe("fuse_get_req", c.Programs[name], nil)
		}
		if err != nil {
			return nil, fmt.Errorf("attach %s: %w", name, err)
		}
		e.links = append(e.links, hook)
	}
	e.reader, err = ringbuf.NewReader(c.Maps["events"])
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Events) Read() (Fault, error) {
	record, err := e.reader.Read()
	if err != nil {
		return Fault{}, err
	}
	if len(record.RawSample) != 24 {
		return Fault{}, io.ErrUnexpectedEOF
	}
	var event Fault
	err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
	return event, err
}
func (e *Events) Close() error {
	e.closeOnce.Do(func() {
		if e.reader != nil {
			_ = e.reader.Close()
		}
		for _, hook := range e.links {
			_ = hook.Close()
		}
		if e.collection != nil {
			e.collection.Close()
		}
	})
	return nil
}
