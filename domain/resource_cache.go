package domain

import "time"

// ResourceCachePolicyContainer optionally narrows the daemon's resource TTL.
type ResourceCachePolicyContainer interface {
	ResourceCacheTTL() time.Duration
	SetResourceCacheTTL(time.Duration)
}
