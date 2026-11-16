package handler

import (
	"strconv"
	"sync/atomic"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/handler/implementations"
)

type resourceOwnerRef struct {
	owner *domain.ResourceOwner
	refs  int
}

var nextResourceOwner atomic.Uint64

func (hs *handlerService) AcquireResourceOwner(c domain.ContainerIface) *domain.ResourceOwner {
	hs.resourceMu.Lock()
	defer hs.resourceMu.Unlock()
	if hs.resourceOwners == nil {
		hs.resourceOwners = make(map[domain.ContainerIface]*resourceOwnerRef)
	}
	ref := hs.resourceOwners[c]
	if ref == nil {
		ref = &resourceOwnerRef{owner: &domain.ResourceOwner{ID: nextResourceOwner.Add(1)}}
		hs.resourceOwners[c] = ref
	}
	ref.refs++
	return ref.owner
}

func (hs *handlerService) ReleaseResourceOwner(owner *domain.ResourceOwner) {
	hs.resourceMu.Lock()
	for c, ref := range hs.resourceOwners {
		if ref.owner != owner {
			continue
		}
		ref.refs--
		if ref.refs != 0 {
			hs.resourceMu.Unlock()
			return
		}
		owner.Close()
		delete(hs.resourceOwners, c)
		hs.resourceMu.Unlock()
		implementations.ReleaseResourceOwner(owner)
		hs.RLock()
		tree := hs.handlerTree
		hs.RUnlock()
		if tree != nil {
			key := "owner:" + strconv.FormatUint(owner.ID, 10)
			tree.Root().Walk(func(_ []byte, value interface{}) bool {
				if cache, ok := value.(interface{ ReleaseResourceSnapshots(string) }); ok {
					cache.ReleaseResourceSnapshots(key)
				}
				return false
			})
		}
		return
	}
	hs.resourceMu.Unlock()
}
