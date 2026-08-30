// Package policy — file-hash cache to skip re-scanning unchanged files.
//
// In a large repo with hundreds of IAM policy files, re-scanning every file
// on every CI run wastes time. This cache stores the SHA-256 hash of each
// scanned file alongside its result. On the next scan, unchanged files return
// the cached result instantly.
//
// Cache is in-memory by default. For persistent CI caching, serialize the
// cache to JSON and restore it from the CI cache layer between runs.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sync"

	"github.com/TushGoel/iam-policy-scanner/pkg/types"
)

// CacheEntry holds a scan result and the file hash it was computed from.
type CacheEntry struct {
	FileHash string           `json:"file_hash"`
	Result   types.ScanResult `json:"result"`
}

// ScanCache stores scan results keyed by file path.
// Thread-safe for concurrent use.
type ScanCache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
	hits    int
	misses  int
}

// NewScanCache returns an empty scan cache.
func NewScanCache() *ScanCache {
	return &ScanCache{
		entries: make(map[string]CacheEntry),
	}
}

// Get returns the cached result for path if the file content matches hash.
// Returns (result, true) on hit, (zero, false) on miss or stale.
func (c *ScanCache) Get(path, currentHash string) (types.ScanResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[path]
	if !ok || entry.FileHash != currentHash {
		c.misses++
		return types.ScanResult{}, false
	}
	c.hits++
	return entry.Result, true
}

// Put stores a scan result for path with its content hash.
func (c *ScanCache) Put(path, hash string, result types.ScanResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[path] = CacheEntry{FileHash: hash, Result: result}
}

// Stats returns cache hit/miss counts.
func (c *ScanCache) Stats() (hits, misses int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses
}

// Size returns the number of cached entries.
func (c *ScanCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// MarshalJSON serialises the cache for persistent storage (e.g. CI cache layer).
func (c *ScanCache) MarshalJSON() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.Marshal(c.entries)
}

// UnmarshalJSON restores a cache from persistent storage.
func (c *ScanCache) UnmarshalJSON(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return json.Unmarshal(data, &c.entries)
}

// HashFile computes the SHA-256 hash of a file's content.
// Returns hex-encoded hash string.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
