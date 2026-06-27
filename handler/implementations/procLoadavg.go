//
// Copyright 2019-2023 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package implementations

import (
	"fmt"
	"sync"
	"time"

	"github.com/nestybox/sysbox-fs/domain"
)

func readLoadavg(req *domain.HandlerRequest) ([]byte, error) {
	node := loadavgSamplerForReq(req)
	return []byte(node.format()), nil
}

type loadavgNode struct {
	key         string
	samplePID   int
	avenrun     [3]uint64
	running     int
	total       int
	lastPID     int
	lastSeen    time.Time
	lastRefresh time.Time
}

type loadavgSamplerState struct {
	sync.Mutex
	once  sync.Once
	nodes map[string]*loadavgNode
}

var loadavgSampler = &loadavgSamplerState{
	nodes: make(map[string]*loadavgNode),
}

func loadavgSamplerForReq(req *domain.HandlerRequest) *loadavgNode {
	loadavgSampler.once.Do(func() {
		go loadavgSampler.run()
	})

	key, samplePID := loadavgNodeKey(req)
	now := time.Now()

	loadavgSampler.Lock()
	node := loadavgSampler.nodes[key]
	if node == nil {
		node = &loadavgNode{
			key:         key,
			samplePID:   samplePID,
			total:       1,
			lastPID:     namespacePID(samplePID),
			lastSeen:    now,
			lastRefresh: now,
		}
		loadavgSampler.nodes[key] = node
	} else {
		node.samplePID = samplePID
		node.lastSeen = now
	}
	loadavgSampler.Unlock()

	loadavgSampler.refreshIfDue(node, now)
	return node
}
func (s *loadavgSamplerState) run() {
	ticker := time.NewTicker(loadavgSampleInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.Lock()
		nodes := make([]*loadavgNode, 0, len(s.nodes))
		now := time.Now()
		for key, node := range s.nodes {
			if now.Sub(node.lastSeen) > loadavgStaleAfter {
				delete(s.nodes, key)
				continue
			}
			nodes = append(nodes, node)
		}
		s.Unlock()

		for _, node := range nodes {
			s.refresh(node)
		}
	}
}

func (s *loadavgSamplerState) refresh(node *loadavgNode) {
	s.Lock()
	samplePID := node.samplePID
	s.Unlock()

	total, running, lastPID := loadavgStatsForPID(samplePID)
	total, running = normalizeLoadavgSample(total, running)

	s.Lock()
	node.avenrun[0] = calcLoadavg(node.avenrun[0], loadavgExp1, uint64(running))
	node.avenrun[1] = calcLoadavg(node.avenrun[1], loadavgExp5, uint64(running))
	node.avenrun[2] = calcLoadavg(node.avenrun[2], loadavgExp15, uint64(running))
	node.running = running
	node.total = total
	node.lastPID = lastPID
	if node.lastPID == 0 {
		node.lastPID = namespacePID(node.samplePID)
	}
	node.lastRefresh = time.Now()
	s.Unlock()
}

func (s *loadavgSamplerState) refreshIfDue(node *loadavgNode, now time.Time) {
	s.Lock()
	due := now.Sub(node.lastRefresh) >= loadavgSampleInterval
	s.Unlock()
	if due {
		s.refresh(node)
	}
}
func normalizeLoadavgSample(total, running int) (int, int) {
	if total == 0 {
		total = 1
	}
	if running > total {
		total = running
	}
	return total, running
}

func calcLoadavg(load, exp, active uint64) uint64 {
	if active > 0 {
		active *= loadavgFixed1
	}
	newLoad := load*exp + active*(loadavgFixed1-exp)
	if active >= load {
		newLoad += loadavgFixed1 - 1
	}
	return newLoad / loadavgFixed1
}

func (n *loadavgNode) format() string {
	loadavgSampler.Lock()
	a := n.avenrun[0] + loadavgFixed1/200
	b := n.avenrun[1] + loadavgFixed1/200
	c := n.avenrun[2] + loadavgFixed1/200
	running := n.running
	total := n.total
	lastPID := n.lastPID
	samplePID := n.samplePID
	loadavgSampler.Unlock()

	if total == 0 {
		total = 1
	}
	if lastPID == 0 {
		lastPID = namespacePID(samplePID)
	}

	return fmt.Sprintf("%d.%02d %d.%02d %d.%02d %d/%d %d\n",
		loadavgInt(a), loadavgFrac(a),
		loadavgInt(b), loadavgFrac(b),
		loadavgInt(c), loadavgFrac(c),
		running, total, lastPID)
}

func loadavgInt(v uint64) uint64 {
	return v >> loadavgFShift
}

func loadavgFrac(v uint64) uint64 {
	return loadavgInt((v & (loadavgFixed1 - 1)) * 100)
}
