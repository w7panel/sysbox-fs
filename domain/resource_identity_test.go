package domain

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestRequestResourceViewCollectedOnce(t *testing.T) {
	var req HandlerRequest
	var reads atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := req.ResourceView(func() ResourceViewIdentity {
				reads.Add(1)
				return ResourceViewIdentity{CgroupV2: "/outer/nested", Pidns: "pid:[123]"}
			})
			if got.CgroupV2 != "/outer/nested" || got.Pidns != "pid:[123]" {
				t.Errorf("wrong view: %#v", got)
			}
		}()
	}
	wg.Wait()
	if reads.Load() != 1 {
		t.Fatalf("identity collected %d times", reads.Load())
	}
}

func TestNewRequestObservesMigration(t *testing.T) {
	path := "/before"
	load := func() ResourceViewIdentity { return ResourceViewIdentity{CgroupV2: path} }
	first := &HandlerRequest{Pid: 123}
	if got := first.ResourceView(load); got.CgroupV2 != "/before" {
		t.Fatal(got)
	}
	path = "/after"
	if got := first.ResourceView(load); got.CgroupV2 != "/before" {
		t.Fatal("request lost consistent view")
	}
	next := &HandlerRequest{Pid: 123}
	if got := next.ResourceView(load); got.CgroupV2 != "/after" {
		t.Fatal("new request reused stale cgroup")
	}
}
