// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"testing"
	"unique"

	cebpf "github.com/cilium/ebpf"
	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
)

// Make accessible for testing
func (t *Tracer) GetEbpfMaps() map[string]*cebpf.Map {
	return t.ebpfMaps
}

func TestSymbolizeKernelFramesCacheMetrics(t *testing.T) {
	kernelFrameCache, err := lru.New[kernelFrameCacheKey, unique.Handle[libpf.Frame]](
		kernelFrameCacheSize, hashKernelFrameCacheKey)
	if err != nil {
		t.Fatalf("failed to create kernel frame cache: %v", err)
	}

	tracer := &Tracer{
		kernelSymbolizer: &kallsyms.Symbolizer{},
		kernelFrameCache: kernelFrameCache,
	}

	cachedFrame := unique.Make(libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0x1233,
	})
	kernelFrameCache.Add(kernelFrameCacheKey{addr: 0x1234}, cachedFrame)

	frames := tracer.symbolizeKernelFrames([]uint64{0x1234, 0x5678}, nil)
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if frames[0] != cachedFrame {
		t.Fatalf("expected cached frame, got %+v", frames[0].Value())
	}

	got := tracer.kernelFrameCacheMetrics()
	want := []metrics.Metric{
		{ID: metrics.IDKernelFrameCacheHit, Value: 1},
		{ID: metrics.IDKernelFrameCacheMiss, Value: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d metrics, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("metric %d: expected %+v, got %+v", i, want[i], got[i])
		}
	}

	frames = tracer.symbolizeKernelFrames([]uint64{0x5678, 0x5678}, frames)
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}

	got = tracer.kernelFrameCacheMetrics()
	want = []metrics.Metric{
		{ID: metrics.IDKernelFrameCacheHit, Value: 0},
		{ID: metrics.IDKernelFrameCacheMiss, Value: 2},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("metric %d for unresolved frames: expected %+v, got %+v", i, want[i], got[i])
		}
	}

	got = tracer.kernelFrameCacheMetrics()
	want = []metrics.Metric{
		{ID: metrics.IDKernelFrameCacheHit, Value: 0},
		{ID: metrics.IDKernelFrameCacheMiss, Value: 0},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("metric %d after reset: expected %+v, got %+v", i, want[i], got[i])
		}
	}
}
