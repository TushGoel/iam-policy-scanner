package policy_test

import (
	"encoding/json"
	"testing"

	"github.com/TushGoel/iam-policy-scanner/internal/policy"
	"github.com/TushGoel/iam-policy-scanner/pkg/types"
)

func sampleResult(name string) types.ScanResult {
	return types.ScanResult{
		PolicyName: name,
		Compliant:  true,
	}
}

func TestCacheHitOnSameHash(t *testing.T) {
	c := policy.NewScanCache()
	c.Put("policy.json", "abc123", sampleResult("policy.json"))
	result, ok := c.Get("policy.json", "abc123")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if result.PolicyName != "policy.json" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestCacheMissOnDifferentHash(t *testing.T) {
	c := policy.NewScanCache()
	c.Put("policy.json", "abc123", sampleResult("policy.json"))
	_, ok := c.Get("policy.json", "xyz999")
	if ok {
		t.Fatal("expected cache miss for different hash (file changed)")
	}
}

func TestCacheMissOnUnknownFile(t *testing.T) {
	c := policy.NewScanCache()
	_, ok := c.Get("unknown.json", "anyhash")
	if ok {
		t.Fatal("expected cache miss for unknown file")
	}
}

func TestCacheStats(t *testing.T) {
	c := policy.NewScanCache()
	c.Put("a.json", "h1", sampleResult("a"))
	c.Get("a.json", "h1") // hit
	c.Get("a.json", "h1") // hit
	c.Get("b.json", "h2") // miss

	hits, misses := c.Stats()
	if hits != 2 {
		t.Errorf("expected 2 hits, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("expected 1 miss, got %d", misses)
	}
}

func TestCacheSerialiseDeserialise(t *testing.T) {
	c := policy.NewScanCache()
	c.Put("p.json", "hash1", sampleResult("p.json"))

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	c2 := policy.NewScanCache()
	if err := json.Unmarshal(data, c2); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	result, ok := c2.Get("p.json", "hash1")
	if !ok {
		t.Fatal("expected cache hit after deserialise")
	}
	if result.PolicyName != "p.json" {
		t.Errorf("unexpected result after deserialise: %v", result)
	}
}
