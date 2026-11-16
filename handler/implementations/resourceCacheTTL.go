package implementations

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

var resourceCacheOverride atomic.Int64

// ConfigureResourceCacheTTL is called before serving requests. An omitted CLI
// flag preserves each resource's existing default (including uptime's 100ms).
func ConfigureResourceCacheTTL(ttl time.Duration, explicit bool) error {
	if ttl <= 0 {
		return fmt.Errorf("resource-cache-ttl must be positive")
	}
	if explicit {
		resourceCacheOverride.Store(int64(ttl))
	} else {
		resourceCacheOverride.Store(0)
	}
	return nil
}

func resourceCacheTTL(req *domain.HandlerRequest, fallback time.Duration) time.Duration {
	ttl := fallback
	if override := resourceCacheOverride.Load(); override > 0 {
		ttl = time.Duration(override)
	}
	if req != nil && req.ResourceCacheTTL > 0 && req.ResourceCacheTTL < ttl {
		ttl = req.ResourceCacheTTL
	}
	return ttl
}
