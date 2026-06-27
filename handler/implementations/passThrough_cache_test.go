package implementations_test

import (
	"sync"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler/implementations"
	"github.com/nestybox/sysbox-fs/nsenter"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sys/unix"
)

func TestPassThrough_ReadWithNS_does_not_hold_container_lock_during_cache_miss_fetch(t *testing.T) {
	// Given
	setupHandlerServiceMock()

	h := &implementations.PassThrough{
		domain.HandlerBase{
			Name:    "PassThrough",
			Path:    "PassThrough",
			Service: hds,
		},
	}

	data := []byte("file content 0123456789")
	n := ios.NewIOnode("node_1", "/proc/sys/net/node_1", 0)
	cntr := css.ContainerCreate(
		"c-read-lock",
		uint32(2001),
		time.Time{},
		231072,
		65535,
		231072,
		65535,
		nil,
		nil,
		css)
	_ = cntr.SetInitProc(cntr.InitPid(), cntr.UID(), cntr.GID())
	cntr.InitProc().CreateNsInodes(123456)

	req := &domain.HandlerRequest{
		Pid:       2001,
		Data:      make([]byte, len(data)),
		Container: cntr,
	}

	nsenterEventReq := &nsenter.NSenterEvent{
		Pid:       req.Pid,
		Namespace: &domain.AllNSs,
		ReqMsg: &domain.NSenterMessage{
			Type: domain.ReadFileRequest,
			Payload: &domain.ReadFilePayload{
				File:        n.Path(),
				Offset:      0,
				Len:         len(data),
				MountSysfs:  false,
				MountProcfs: true,
			},
		},
	}
	nsenterEventResp := &nsenter.NSenterEvent{
		ResMsg: &domain.NSenterMessage{
			Type:    domain.ReadFileResponse,
			Payload: data,
		},
	}

	fetchStarted := make(chan struct{})
	releaseFetch := make(chan struct{})
	nss.On(
		"NewEvent",
		req.Pid,
		uint32(0),
		uint32(0),
		&domain.AllNSs,
		uint32(unix.CLONE_NEWNS),
		nsenterEventReq.ReqMsg,
		(*domain.NSenterMessage)(nil),
		false).Return(nsenterEventReq)
	nss.On("SendRequestEvent", nsenterEventReq).Return(nil)
	nss.On("ReceiveResponseEvent", nsenterEventReq).
		Run(func(args mock.Arguments) {
			close(fetchStarted)
			<-releaseFetch
		}).
		Return(nsenterEventResp.ResMsg)

	var wg sync.WaitGroup
	readDone := make(chan struct{})
	var got int
	var readErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, readErr = h.ReadWithNS(n, req, domain.AllNSs)
		close(readDone)
	}()

	<-fetchStarted
	lockAcquired := make(chan struct{})
	go func() {
		cntr.Lock()
		cntr.Unlock()
		close(lockAcquired)
	}()

	// When / Then
	select {
	case <-lockAcquired:
	case <-time.After(100 * time.Millisecond):
		close(releaseFetch)
		<-readDone
		wg.Wait()
		nss.ExpectedCalls = nil
		t.Fatalf("container lock remained held while passthrough cache miss fetch was blocked")
	}

	close(releaseFetch)
	<-readDone
	wg.Wait()
	if readErr != nil {
		t.Fatalf("PassThrough.ReadWithNS() error = %v", readErr)
	}
	if got != len(data) {
		t.Fatalf("PassThrough.ReadWithNS() = %v, want %v", got, len(data))
	}

	nss.AssertExpectations(t)
	nss.ExpectedCalls = nil
}

func TestPassThrough_ReadWithNS_coalesces_concurrent_cache_miss_fetches(t *testing.T) {
	// Given
	setupHandlerServiceMock()

	h := &implementations.PassThrough{
		domain.HandlerBase{
			Name:    "PassThrough",
			Path:    "PassThrough",
			Service: hds,
		},
	}

	data := []byte("file content 0123456789")
	n := ios.NewIOnode("node_1", "/proc/sys/net/node_1", 0)
	cntr := css.ContainerCreate(
		"c-read-singleflight",
		uint32(2002),
		time.Time{},
		231072,
		65535,
		231072,
		65535,
		nil,
		nil,
		css)
	_ = cntr.SetInitProc(cntr.InitPid(), cntr.UID(), cntr.GID())
	cntr.InitProc().CreateNsInodes(123456)
	_, err := cntr.InitProc().NsInodes()
	if err != nil {
		t.Fatalf("Process.NsInodes() error = %v", err)
	}

	nsenterEventReq := &nsenter.NSenterEvent{
		Pid:       2002,
		Namespace: &domain.AllNSs,
		ReqMsg: &domain.NSenterMessage{
			Type: domain.ReadFileRequest,
			Payload: &domain.ReadFilePayload{
				File:        n.Path(),
				Offset:      0,
				Len:         len(data),
				MountSysfs:  false,
				MountProcfs: true,
			},
		},
	}
	nsenterEventResp := &nsenter.NSenterEvent{
		ResMsg: &domain.NSenterMessage{
			Type:    domain.ReadFileResponse,
			Payload: data,
		},
	}

	fetchStarted := make(chan struct{})
	releaseFetch := make(chan struct{})
	var once sync.Once
	nss.On(
		"NewEvent",
		uint32(2002),
		uint32(0),
		uint32(0),
		&domain.AllNSs,
		uint32(unix.CLONE_NEWNS),
		nsenterEventReq.ReqMsg,
		(*domain.NSenterMessage)(nil),
		false).Return(nsenterEventReq).Once()
	nss.On("SendRequestEvent", nsenterEventReq).Return(nil).Once()
	nss.On("ReceiveResponseEvent", nsenterEventReq).
		Run(func(args mock.Arguments) {
			once.Do(func() { close(fetchStarted) })
			<-releaseFetch
		}).
		Return(nsenterEventResp.ResMsg).
		Once()

	readerCount := 2
	startReaders := make(chan struct{})
	readDone := make(chan struct{}, readerCount)
	readErrs := make(chan error, readerCount)
	readSizes := make(chan int, readerCount)
	for i := 0; i < readerCount; i++ {
		go func() {
			<-startReaders
			req := &domain.HandlerRequest{
				Pid:       2002,
				Data:      make([]byte, len(data)),
				Container: cntr,
			}
			sz, err := h.ReadWithNS(n, req, domain.AllNSs)
			readSizes <- sz
			readErrs <- err
			readDone <- struct{}{}
		}()
	}

	// When
	close(startReaders)
	<-fetchStarted
	close(releaseFetch)
	for i := 0; i < readerCount; i++ {
		<-readDone
	}

	// Then
	for i := 0; i < readerCount; i++ {
		if err := <-readErrs; err != nil {
			t.Fatalf("PassThrough.ReadWithNS() error = %v", err)
		}
		if got := <-readSizes; got != len(data) {
			t.Fatalf("PassThrough.ReadWithNS() = %v, want %v", got, len(data))
		}
	}

	nss.AssertExpectations(t)
	nss.ExpectedCalls = nil
}
