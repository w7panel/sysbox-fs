package domain

import "sync/atomic"

// ResourceOwner identifies one lifetime of shared FUSE resource state.
type ResourceOwner struct {
	ID     uint64
	closed atomic.Bool
}

func (o *ResourceOwner) Closed() bool { return o.closed.Load() }
func (o *ResourceOwner) Close()       { o.closed.Store(true) }
