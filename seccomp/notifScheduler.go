package seccomp

import "sync"

const maxSeccompNotifInFlight = 128

type processNotifFn func(req *sysRequest, fd int32, cntrID string)

type notifScheduler struct {
	pending    sync.WaitGroup
	limit      chan struct{}
	pidTracker *seccompNotifPidTracker
}

func newNotifScheduler(maxInFlight int, pidTracker *seccompNotifPidTracker) *notifScheduler {
	return &notifScheduler{
		limit:      make(chan struct{}, maxInFlight),
		pidTracker: pidTracker,
	}
}

func (s *notifScheduler) Schedule(req *sysRequest, fd int32, cntrID string, processFn processNotifFn) {
	s.pending.Add(1)
	s.limit <- struct{}{}
	go func() {
		defer s.pending.Done()
		defer func() { <-s.limit }()

		s.pidTracker.Lock(req.Pid)
		defer s.pidTracker.Unlock(req.Pid)

		processFn(req, fd, cntrID)
	}()
}
