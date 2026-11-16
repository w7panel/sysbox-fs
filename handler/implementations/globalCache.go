package implementations

import "time"

const globalCacheTTL = 30 * time.Second

// Only immutable host inputs belong here. Callers must still derive CPU and
// disk views from the requesting process's cgroup, never cache those globally.
var globalCache byteSnapshots

func cachedHostFile(path string) ([]byte, error) {
	return globalCache.get(path, "", nil, false, time.Now(), globalCacheTTL,
		func() ([]byte, error) { return hostFile(path) })
}
