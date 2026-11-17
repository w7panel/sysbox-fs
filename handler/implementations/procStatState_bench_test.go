package implementations

import (
	"fmt"
	"testing"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

func BenchmarkProcStatStateLookup1000(b *testing.B) {
	now := time.Now()
	procStatStatesMu.Lock()
	previous, previousPrune := procStatStates, procStatNextPrune
	procStatStates = make(map[string]*procStatState, 1001)
	procStatNextPrune = time.Time{}
	for i := 0; i < 1000; i++ {
		procStatStates[fmt.Sprintf("view-%d", i)] = &procStatState{lastSeen: now}
	}
	procStatStatesMu.Unlock()
	defer func() {
		procStatStatesMu.Lock()
		procStatStates, procStatNextPrune = previous, previousPrune
		procStatStatesMu.Unlock()
	}()

	req := &domain.HandlerRequest{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		procStatStateForKey(req, "hot", now)
	}
}
