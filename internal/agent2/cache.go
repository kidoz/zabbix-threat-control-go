package agent2

import (
	"sync"

	"github.com/kidoz/zabbix-threat-control-go/internal/scanner"
)

// ScanCache holds the most recent scan results in a thread-safe manner.
type ScanCache struct {
	mu      sync.RWMutex
	results *scanner.ScanResults
	stats   scanner.Statistics
}

// NewScanCache creates a new empty cache.
func NewScanCache() *ScanCache {
	return &ScanCache{}
}

// Update replaces the cached data atomically.
func (c *ScanCache) Update(results *scanner.ScanResults, stats scanner.Statistics) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = results
	c.stats = stats
}

// Results returns the cached scan results (may be nil if no scan has run).
func (c *ScanCache) Results() *scanner.ScanResults {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.results
}

// Stats returns the cached statistics.
func (c *ScanCache) Stats() scanner.Statistics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}
