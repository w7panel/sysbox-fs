package seccomp

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// systemd owns a duplicate of each seccomp listener across daemon replacement.
// A notify barrier alone does not report a full/disabled store; enumerate it
// afterwards and verify the submitted descriptor before acknowledging runc.
type fdStore struct {
	mu     sync.Mutex
	notify string
	bus    *dbus.Conn
	unit   dbus.BusObject
	names  map[int]string
}

type storedFD struct {
	Name      string
	Mode      uint32
	DevMajor  uint32
	DevMinor  uint32
	Inode     uint64
	RdevMajor uint32
	RdevMinor uint32
	Path      string
	Flags     uint32
}

func newFDStore() (*fdStore, error) {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return nil, fmt.Errorf("session recovery requires systemd NOTIFY_SOCKET and fd store")
	}
	bus, err := dbus.SystemBusPrivate()
	if err != nil {
		return nil, err
	}
	if err := bus.Auth(nil); err != nil {
		bus.Close()
		return nil, err
	}
	if err := bus.Hello(); err != nil {
		bus.Close()
		return nil, err
	}
	var path dbus.ObjectPath
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = bus.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnitByPID", 0, uint32(os.Getpid())).Store(&path)
	if err != nil {
		bus.Close()
		return nil, err
	}
	store := &fdStore{notify: address, bus: bus, unit: bus.Object("org.freedesktop.systemd1", path), names: make(map[int]string)}
	max, err := store.unit.GetProperty("org.freedesktop.systemd1.Service.FileDescriptorStoreMax")
	if err != nil {
		bus.Close()
		return nil, err
	}
	capacity, ok := max.Value().(uint32)
	if !ok || capacity == 0 {
		bus.Close()
		return nil, fmt.Errorf("session recovery requires FileDescriptorStoreMax>0")
	}
	preserve, err := store.unit.GetProperty("org.freedesktop.systemd1.Service.FileDescriptorStorePreserve")
	if err != nil {
		bus.Close()
		return nil, err
	}
	if preserve.Value() != "yes" {
		bus.Close()
		return nil, fmt.Errorf("session recovery requires FileDescriptorStorePreserve=yes")
	}
	if _, err := store.entries(); err != nil {
		bus.Close()
		return nil, fmt.Errorf("systemd fd store unavailable: %w", err)
	}
	return store, nil
}

func (s *fdStore) entries() ([]storedFD, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var entries []storedFD
	err := s.unit.CallWithContext(ctx, "org.freedesktop.systemd1.Service.DumpFileDescriptorStore", 0).Store(&entries)
	return entries, err
}

func notifyWithBarrier(address, message string, fd int) error {
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	send := func(message string, rights []byte) error {
		var sendErr error
		err := raw.Write(func(socket uintptr) bool {
			_, sendErr = unix.SendmsgN(int(socket), []byte(message), rights, nil, 0)
			return sendErr != unix.EAGAIN && sendErr != unix.EWOULDBLOCK
		})
		if err != nil {
			return err
		}
		return sendErr
	}
	var rights []byte
	if fd >= 0 {
		rights = unix.UnixRights(fd)
	}
	if err := send(message, rights); err != nil {
		return err
	}
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return err
	}
	defer unix.Close(pipe[0])
	err = send("BARRIER=1", unix.UnixRights(pipe[1]))
	unix.Close(pipe[1])
	if err != nil {
		return err
	}
	poll := []unix.PollFd{{Fd: int32(pipe[0]), Events: unix.POLLIN}}
	deadline := time.Now().Add(5 * time.Second)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return fmt.Errorf("systemd fd store barrier timed out")
		}
		_, err := unix.Poll(poll, int(left.Milliseconds())+1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if poll[0].Revents&unix.POLLHUP != 0 {
			return nil
		}
	}
}

func (s *fdStore) add(fd int, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Track even a failed/uncertain send so the rejected registration can
	// remove a descriptor the manager may already have accepted.
	s.names[fd] = name
	if err := notifyWithBarrier(s.notify, "FDSTORE=1\nFDPOLL=0\nFDNAME="+name, fd); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	entries, err := s.entries()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name == name && entry.Inode == stat.Ino && entry.DevMajor == unix.Major(uint64(stat.Dev)) && entry.DevMinor == unix.Minor(uint64(stat.Dev)) {
			return nil
		}
	}
	return fmt.Errorf("systemd did not retain seccomp listener %s", name)
}

func (s *fdStore) remove(fd int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, ok := s.names[fd]
	if !ok {
		return nil
	}
	if err := notifyWithBarrier(s.notify, "FDSTOREREMOVE=1\nFDNAME="+name, -1); err != nil {
		return err
	}
	entries, err := s.entries()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name == name {
			return fmt.Errorf("systemd retained removed listener %s", name)
		}
	}
	delete(s.names, fd)
	return nil
}
