package seccomp

import "sync"

const maxSeccompNotifInFlight = 128

type processNotifFn func(req *sysRequest, fd int32, cntrID string)

type notifScheduler struct {
	limit      chan struct{}
	pidTracker *seccompNotifPidTracker
	wg         sync.WaitGroup
}

func newNotifScheduler(maxInFlight int, pidTracker *seccompNotifPidTracker) *notifScheduler {
	return &notifScheduler{
		limit:      make(chan struct{}, maxInFlight),
		pidTracker: pidTracker,
	}
}

func (s *notifScheduler) Schedule(req *sysRequest, fd int32, cntrID string, processFn processNotifFn) {
	s.limit <- struct{}{}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.limit }()

		s.pidTracker.Lock(req.Pid)
		defer s.pidTracker.Unlock(req.Pid)

		processFn(req, fd, cntrID)
	}()
}

func (s *notifScheduler) Wait() {
	s.wg.Wait()
}
