package handler

import (
	iradix "github.com/hashicorp/go-immutable-radix"
	"strconv"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
)

type resourceTestContainer struct{ domain.ContainerIface }

func TestResourceOwnerSharedLifetime(t *testing.T) {
	hs := &handlerService{}
	c := &resourceTestContainer{}
	first := hs.AcquireResourceOwner(c)
	second := hs.AcquireResourceOwner(c)
	if first != second {
		t.Fatal("shared state got distinct owners")
	}
	hs.ReleaseResourceOwner(first)
	if first.Closed() {
		t.Fatal("shared state closed before last user")
	}
	hs.ReleaseResourceOwner(second)
	if !first.Closed() || len(hs.resourceOwners) != 0 {
		t.Fatal("last user did not release state")
	}
	next := hs.AcquireResourceOwner(c)
	if next.ID == first.ID || next.Closed() {
		t.Fatal("recreated state reused closed lifetime")
	}
	hs.ReleaseResourceOwner(first)
	if next.Closed() {
		t.Fatal("late release closed new lifetime")
	}
	hs.ReleaseResourceOwner(next)
}

func TestResourceOwnerDistinctContainers(t *testing.T) {
	hs := &handlerService{}
	first := hs.AcquireResourceOwner(&resourceTestContainer{})
	second := hs.AcquireResourceOwner(&resourceTestContainer{})
	if first.ID == second.ID {
		t.Fatal("distinct state reused owner")
	}
	hs.ReleaseResourceOwner(first)
	if second.Closed() {
		t.Fatal("unrelated state was closed")
	}
	hs.ReleaseResourceOwner(second)
}

type resourceTestHandler struct {
	domain.HandlerIface
	released []string
}

func (h *resourceTestHandler) ReleaseResourceSnapshots(owner string) {
	h.released = append(h.released, owner)
}

func TestLastResourceUserReleasesRegisteredCaches(t *testing.T) {
	cache := &resourceTestHandler{}
	tree, _, _ := iradix.New().Insert([]byte("/proc/stat"), cache)
	hs := &handlerService{handlerTree: tree}
	c := &resourceTestContainer{}
	owner := hs.AcquireResourceOwner(c)
	hs.AcquireResourceOwner(c)
	hs.ReleaseResourceOwner(owner)
	if len(cache.released) != 0 {
		t.Fatal("shared cache released early")
	}
	hs.ReleaseResourceOwner(owner)
	if len(cache.released) != 1 || cache.released[0] != "owner:"+strconv.FormatUint(owner.ID, 10) {
		t.Fatal("registered cache was not released")
	}
}
