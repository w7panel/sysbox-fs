package seccomp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nestybox/sysbox-runc/libcontainer/system"
	"golang.org/x/sys/unix"
)

type listenerIdentity struct {
	container string
	initPID   uint32
	initStart uint64
	pid       uint32
	start     uint64
}

func (i listenerIdentity) name() (string, error) {
	name := fmt.Sprintf("seccomp.%s.%d.%d.%d.%d", base64.RawURLEncoding.EncodeToString([]byte(i.container)), i.initPID, i.initStart, i.pid, i.start)
	if len(name) > 255 {
		return "", fmt.Errorf("container ID exceeds systemd FDNAME limit")
	}
	return name, nil
}

func parseListenerIdentity(name string) (listenerIdentity, error) {
	var i listenerIdentity
	parts := strings.Split(name, ".")
	if len(parts) != 6 || parts[0] != "seccomp" {
		return i, fmt.Errorf("invalid seccomp FDNAME %q", name)
	}
	id, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(id) == 0 {
		return i, fmt.Errorf("invalid FDNAME container")
	}
	i.container = string(id)
	values := make([]uint64, 4)
	for n := range values {
		bits := 64
		if n%2 == 0 {
			bits = 32
		}
		values[n], err = strconv.ParseUint(parts[n+2], 10, bits)
		if err != nil || values[n] == 0 {
			return i, fmt.Errorf("invalid FDNAME process identity")
		}
	}
	i.initPID, i.initStart, i.pid, i.start = uint32(values[0]), values[1], uint32(values[2]), values[3]
	return i, nil
}

// EnableRecovery must run before Setup, before subprocesses could inherit the
// activation descriptors. RestoreSessions follows container-state restoration.
func (scs *SyscallMonitorService) EnableRecovery() error {
	store, err := newFDStore()
	if err != nil {
		return err
	}
	if os.Getenv("LISTEN_FDS") != "" {
		pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
		if err != nil || pid != os.Getpid() {
			store.bus.Close()
			return fmt.Errorf("invalid systemd LISTEN_PID")
		}
		count, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
		names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
		if count == 0 && os.Getenv("LISTEN_FDNAMES") == "" {
			names = nil
		}
		if err != nil || count < 0 || count != len(names) {
			store.bus.Close()
			return fmt.Errorf("invalid systemd activation descriptors")
		}
		for n, name := range names {
			fd := n + 3
			unix.CloseOnExec(fd)
			if _, err := parseListenerIdentity(name); err != nil {
				store.bus.Close()
				return err
			}
			scs.inheritedListeners = append(scs.inheritedListeners, fd)
			store.names[fd] = name
		}
	}
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	scs.fdStore = store
	return nil
}

func (t *syscallTracer) retainListener(pid uint32, container string, fd int) error {
	cntr := t.service.css.ContainerLookupById(container)
	if cntr == nil || cntr.InitPid() == 0 {
		return fmt.Errorf("seccomp container %s is not registered", container)
	}
	initStat, err := system.Stat(int(cntr.InitPid()))
	if err != nil {
		return err
	}
	stat, err := system.Stat(int(pid))
	if err != nil {
		return err
	}
	name, err := (listenerIdentity{container, cntr.InitPid(), initStat.StartTime, pid, stat.StartTime}).name()
	if err != nil {
		return err
	}
	return t.service.fdStore.add(fd, name)
}

func (scs *SyscallMonitorService) RestoreSessions() error {
	if scs.fdStore == nil {
		return nil
	}
	for _, fd := range scs.inheritedListeners {
		scs.fdStore.mu.Lock()
		name := scs.fdStore.names[fd]
		scs.fdStore.mu.Unlock()
		identity, err := parseListenerIdentity(name)
		if err != nil {
			return err
		}
		target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil || target != "anon_inode:seccomp notify" {
			return fmt.Errorf("inherited fd %d is not a seccomp listener: %q", fd, target)
		}
		cntr := scs.css.ContainerLookupById(identity.container)
		if cntr == nil || cntr.InitPid() != identity.initPID {
			if err := scs.fdStore.remove(fd); err != nil {
				return err
			}
			unix.Close(fd)
			continue
		}
		initStat, err := system.Stat(int(identity.initPID))
		if err != nil || initStat.StartTime != identity.initStart {
			return fmt.Errorf("container %s init identity changed", identity.container)
		}
		// With unused-filter notifications the original process may have exited
		// while descendants still use its filter. Do not discard their listener.
		stat, err := system.Stat(int(identity.pid))
		gone := errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH)
		if err != nil && !gone {
			return err
		}
		if gone || stat.StartTime != identity.start {
			if !scs.tracer.seccompUnusedNotif {
				return fmt.Errorf("seccomp tracee %d exited without unused-filter support", identity.pid)
			}
			// The original pid no longer identifies this filter's users.
			identity.pid = 0
		}
		pidfd := scs.tracer.seccompSessionPidfd(int32(identity.pid), identity.container, int32(fd))
		session := seccompSession{identity.pid, int32(fd), int32(pidfd), identity.container}
		scs.tracer.seccompSessionAdd(session)
		go scs.tracer.pollSession(session)
	}
	scs.inheritedListeners = nil
	return nil
}

// Quiesce stops admission and drains every notification already received from
// the kernel before the caller checkpoints container state. Pending kernel
// notifications and their listener descriptors remain intact for the next FS.
func (scs *SyscallMonitorService) Quiesce() error {
	t := scs.tracer
	if t == nil {
		return nil
	}
	t.recoveryMu.Lock()
	t.quiescing = true
	var err error
	if t.srv != nil {
		err = t.srv.Close()
	}
	t.recoveryMu.Unlock()
	if err != nil {
		return err
	}
	t.seccompNotifSched.pending.Wait()
	return nil
}
