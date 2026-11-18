package implementations

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
	"golang.org/x/sync/singleflight"
)

type resourceSnapshot struct {
	data      []byte
	createdAt time.Time
	expiresAt time.Time
	owner     string
}

// byteSnapshots shares only completed, immutable byte slices. Collection never
// holds the map lock, so unrelated resource views can refresh concurrently.
type byteSnapshots struct {
	mu        sync.RWMutex
	entries   map[string]resourceSnapshot
	nextPrune time.Time
	misses    singleflight.Group
}

func (c *byteSnapshots) get(key, owner string, token *domain.ResourceOwner, continuation bool, now time.Time, ttl time.Duration, read func() ([]byte, error)) ([]byte, error) {
	if token != nil && token.Closed() {
		return nil, os.ErrNotExist
	}
	c.mu.RLock()
	prune := !now.Before(c.nextPrune)
	c.mu.RUnlock()
	if prune {
		c.mu.Lock()
		if !now.Before(c.nextPrune) {
			for k, v := range c.entries {
				if !(continuation && k == key) && !now.Before(v.expiresAt) {
					delete(c.entries, k)
				}
			}
			c.nextPrune = now.Add(max(ttl, time.Minute))
		}
		c.mu.Unlock()
	}
	if data, ok := c.cached(key, continuation, now, ttl); ok {
		return data, nil
	}
	value, err, _ := c.misses.Do(key, func() (interface{}, error) {
		if token != nil && token.Closed() {
			return nil, os.ErrNotExist
		}
		if data, ok := c.cached(key, continuation, now, ttl); ok {
			return data, nil
		}
		data, err := read()
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if token != nil && token.Closed() {
			return nil, os.ErrNotExist
		}
		if c.entries == nil {
			c.entries = make(map[string]resourceSnapshot)
		}
		c.entries[key] = resourceSnapshot{data: data, createdAt: now, expiresAt: now.Add(ttl), owner: owner}
		return data, nil
	})
	if err != nil {
		return nil, err
	}
	return value.([]byte), nil
}

func (c *byteSnapshots) cached(key string, continuation bool, now time.Time, ttl time.Duration) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot, ok := c.entries[key]
	return snapshot.data, ok && (continuation || now.Sub(snapshot.createdAt) < ttl)
}

func (c *byteSnapshots) release(owner string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, snapshot := range c.entries {
		if snapshot.owner == owner {
			delete(c.entries, key)
		}
	}
}

func releaseResourceSnapshots(owner string) {
	procUptimeSnapshots.release(owner)
}

func resourceOwnerKey(req *domain.HandlerRequest) string {
	if req.ResourceOwner != nil {
		return "owner:" + strconv.FormatUint(req.ResourceOwner.ID, 10)
	}
	if req.Container != nil {
		return fmt.Sprintf("container:%p", req.Container)
	}
	return fmt.Sprintf("pid:%d", req.Pid)
}

func resourceViewKey(req *domain.HandlerRequest) string {
	identity := requestResourceView(req)
	cg := cgroupView{v2Path: identity.CgroupV2, v1: identity.CgroupV1}
	ns := identity.Pidns
	return resourceViewKeyFor(req, cg, ns)
}

func resourceViewKeyFor(req *domain.HandlerRequest, cg cgroupView, ns string) string {
	if ns == "" || (cg.v2Path == "" && len(cg.v1) == 0) {
		return fmt.Sprintf("%s\x00pid:%d", resourceOwnerKey(req), req.Pid)
	}
	return resourceOwnerKey(req) + "\x00" + cgroupViewKey(cg) + "\x00" + ns
}

func cgroupViewKey(cg cgroupView) string {
	if len(cg.v1) == 0 {
		return "v2\x00" + cg.v2Path
	}
	parts := []string{"v2", cg.v2Path}
	controllers := make([]string, 0, len(cg.v1))
	for controller := range cg.v1 {
		controllers = append(controllers, controller)
	}
	sort.Strings(controllers)
	for _, controller := range controllers {
		parts = append(parts, controller, cg.v1[controller])
	}
	return strings.Join(parts, "\x00")
}
