package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	systemd "github.com/coreos/go-systemd/daemon"
	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"github.com/nestybox/sysbox-fs/recovery"
	"github.com/nestybox/sysbox-fs/state"
	libutils "github.com/nestybox/sysbox-libs/utils"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const fsRestartFile = "/run/sysbox/fs-restart.json"

type recoveryRunner struct {
	events                             *recovery.Events
	css                                domain.ContainerStateServiceIface
	root                               string
	records                            map[uint32][]state.RestartContainer
	mu                                 sync.Mutex
	repaired                           sync.Map
	fallbackDone                       sync.Map
	silentDone                         sync.Map
	attempts, succeeded, failed, stale uint64
	faultCounts                        map[faultProcess]int
}

type faultProcess struct {
	pid       uint32
	namespace uint64
	device    uint32
}

const frequentFaultThreshold = 5

type repairResult int

const (
	repairFailed repairResult = iota
	repairUnchanged
	repairReplaced
)

func prepareRecovery(css domain.ContainerStateServiceIface, fss *fuse.FuseServerService, root string) (*recoveryRunner, error) {
	saved, err := state.ReadRestart(fsRestartFile)
	if err != nil {
		return nil, err
	}
	if saved == nil {
		entries, err := os.ReadDir(root)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		for _, entry := range entries {
			// A host reboot leaves empty mountpoint directories but no /run
			// checkpoint. Remove only empty directories; mounts fail EBUSY
			// and populated paths are preserved for manual recovery.
			if !entry.IsDir() {
				return nil, fmt.Errorf("unexpected FUSE root entry %s", entry.Name())
			}
			if err := os.Remove(filepath.Join(root, entry.Name())); err != nil {
				return nil, fmt.Errorf("cannot adopt existing FUSE mounts without a checkpoint: %w", err)
			}
		}
	}
	r := &recoveryRunner{css: css, root: root, records: make(map[uint32][]state.RestartContainer), faultCounts: make(map[faultProcess]int)}
	var devices []uint32
	if saved != nil {
		for _, c := range saved.Containers {
			for _, dev := range c.Devices {
				if len(r.records[dev]) == 0 {
					devices = append(devices, dev)
				}
				r.records[dev] = append(r.records[dev], c)
			}
		}
	}
	r.events, err = recovery.NewEvents(devices)
	if err != nil {
		return nil, err
	}
	if saved != nil {
		saved.Clean = false
		if err = state.WriteRestart(fsRestartFile, saved); err == nil {
			err = state.RestoreRestart(css, saved)
		}
	} else {
		err = state.SaveRestart(css, fss.StateContainer, fsRestartFile, root, false)
	}
	if err != nil {
		r.events.Close()
		return nil, err
	}
	return r, nil
}

func (r *recoveryRunner) repair(ctx context.Context, pid uint32, c state.RestartContainer, deviceNums []uint32) repairResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.css.ContainerLookupById(c.ID)
	if ctx.Err() != nil || current == nil || current.InitPid() != c.PID {
		return repairFailed
	}
	start, err := state.ProcessStartTime(c.PID)
	if err != nil || start != c.StartTime {
		return repairFailed
	}
	devices := make([]recovery.Device, 0, len(deviceNums))
	for _, dev := range deviceNums {
		devices = append(devices, recovery.Device{Major: dev >> 20, Minor: dev & ((1 << 20) - 1)})
	}
	r.attempts++
	started := time.Now()
	targetNS, targetErr := os.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	outerNS, outerErr := os.Stat(fmt.Sprintf("/proc/%d/ns/mnt", c.PID))
	sameNamespace := targetErr == nil && outerErr == nil && os.SameFile(targetNS, outerNS)
	paths, err := recovery.RepairMounts(ctx, int(pid), r.root, c.ID, devices)
	if len(paths) > 0 && sameNamespace {
		if refreshErr := state.RefreshRecoveredMounts(r.css, c.ID, paths); refreshErr != nil {
			err = fmt.Errorf("repair error: %v; refresh mount policy: %w", err, refreshErr)
		}
	}
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			r.stale++
			return repairFailed
		}
		r.failed++
		logrus.WithError(err).WithField("container", c.ID).WithField("pid", pid).WithField("duration_ms", time.Since(started).Milliseconds()).Error("FUSE recovery incomplete")
		return repairFailed
	} else if len(paths) > 0 {
		r.succeeded++
		logrus.WithField("container", c.ID).WithField("pid", pid).WithField("duration_ms", time.Since(started).Milliseconds()).Info("FUSE mounts recovered; reopen stale descriptors")
		return repairReplaced
	} else {
		r.stale++
		return repairUnchanged
	}
}

func (r *recoveryRunner) run(ctx context.Context) error {
	go func() { <-ctx.Done(); r.events.Close() }()
	// The minute fallback inspects only registered containers and their cgroups.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.mu.Lock()
				r.faultCounts = make(map[faultProcess]int)
				r.mu.Unlock()
				seen := make(map[string]bool)
				for _, owners := range r.records {
					for _, c := range owners {
						if seen[c.ID] {
							continue
						}
						seen[c.ID] = true
						start, err := state.ProcessStartTime(c.PID)
						if err != nil || start != c.StartTime {
							continue
						}
						r.repairSilentNamespaces(ctx, c)
						if _, done := r.fallbackDone.Load(c.ID); done {
							continue
						}
						// Only checkpointed, disconnected devices are eligible. Inspect
						// mount metadata directly rather than block on a FUSE stat.
						if r.repair(ctx, c.PID, c, c.Devices) != repairFailed {
							r.fallbackDone.Store(c.ID, struct{}{})
						}
					}
				}
				r.mu.Lock()
				logrus.WithFields(logrus.Fields{"attempts": r.attempts, "successes": r.succeeded, "failures": r.failed, "old_fd_events": r.stale}).Info("FUSE recovery counters")
				r.mu.Unlock()
			}
		}
	}()
	for {
		fault, err := r.events.Read()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("FUSE fault event stream stopped: %w", err)
		}
		r.mu.Lock()
		process := faultProcess{fault.PID, fault.Namespace, fault.Device}
		r.faultCounts[process]++
		frequent := r.faultCounts[process] == frequentFaultThreshold
		r.mu.Unlock()
		if frequent {
			logrus.WithFields(logrus.Fields{"pid": fault.PID, "namespace": fault.Namespace, "device": fault.Device}).Warn("frequent stale FUSE reads; process must reopen old descriptors")
		}
		key := struct {
			namespace uint64
			device    uint32
		}{fault.Namespace, fault.Device}
		if _, done := r.repaired.Load(key); done {
			continue
		}
		owners := r.records[fault.Device]
		for _, c := range owners {
			pid, err := recoveryPID(ctx, fault, c)
			if err != nil {
				continue
			}
			// The helper pins and revalidates the namespace and mounts before mutation.
			result := r.repair(ctx, pid, c, []uint32{fault.Device})
			if result == repairReplaced || result == repairUnchanged && len(owners) == 1 {
				r.repaired.Store(key, struct{}{})
				break
			}
		}
	}
}

func (r *recoveryRunner) repairSilentNamespaces(ctx context.Context, c state.RestartContainer) {
	root, err := containerCgroupRoot(c.PID)
	if err != nil {
		return
	}
	namespaces, err := findContainerNamespaces(ctx, root)
	if err != nil {
		logrus.WithError(err).WithField("container", c.ID).Warn("FUSE namespace fallback scan failed")
		return
	}
	var outer unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", c.PID), &outer) != nil {
		return
	}
	for namespace, pid := range namespaces {
		if namespace != outer.Ino {
			key := struct {
				container string
				namespace uint64
			}{c.ID, namespace}
			if _, done := r.silentDone.Load(key); done {
				continue
			}
			if r.repair(ctx, pid, c, c.Devices) != repairFailed {
				r.silentDone.Store(key, struct{}{})
			}
		}
	}
}

func runRecoverable(r *recoveryRunner, ipc domain.IpcServiceIface, fss *fuse.FuseServerService, quiesce func() error, profile interface{ Stop() }) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eventResult := make(chan error, 1)
	go func() { eventResult <- r.run(ctx) }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	if err := libutils.CreatePidFile("sysbox-fs", sysboxFsPidFile); err != nil {
		return err
	}
	defer libutils.DestroyPidFile(sysboxFsPidFile)
	result := make(chan error, 1)
	go func() { result <- ipc.Init() }()
	systemd.SdNotify(false, systemd.SdNotifyReady)
	select {
	case err := <-result:
		return err
	case err := <-eventResult:
		return err
	case <-signals:
	}
	systemd.SdNotify(false, systemd.SdNotifyStopping)
	ipc.(interface{ Stop() }).Stop()
	if err := quiesce(); err != nil {
		return err
	}
	cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	fss.Quiesce()
	if err := state.SaveRestart(r.css, fss.StateContainer, fsRestartFile, r.root, true); err != nil {
		return err
	}
	if err := fss.DetachForRestart(); err != nil {
		// A partially detached host tree must not be treated as recoverable.
		saved, readErr := state.ReadRestart(fsRestartFile)
		if readErr == nil && saved != nil {
			saved.Clean = false
			if writeErr := state.WriteRestart(fsRestartFile, saved); writeErr != nil {
				return fmt.Errorf("detach: %v; invalidate checkpoint: %w", err, writeErr)
			}
		}
		return err
	}
	if profile != nil {
		profile.Stop()
	}
	return nil
}
