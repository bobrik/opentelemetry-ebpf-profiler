package processmanager

import (
	"os"
	"runtime"
	"slices"
	"testing"
	"time"
	"unique"

	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	golang "go.opentelemetry.io/ebpf-profiler/interpreter/go"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type traceCapture struct {
	traces []*libpf.Trace
}

func (tc *traceCapture) ReportTraceEvent(trace *libpf.Trace, _ *samples.TraceEventMeta) error {
	tc.traces = append(tc.traces, trace)
	return nil
}

type fakeKernelSymbols struct {
	snapshot *fakeKernelSymbolsSnapshot
}

func (f fakeKernelSymbols) Snapshot() kernelSymbolsSnapshot {
	return f.snapshot
}

type fakeKernelSymbolsSnapshot struct {
	validGenerations map[kallsyms.Generation]bool
	resolutions      map[libpf.Address]kallsyms.AddressResolution
	resolveCount     int
}

func (s *fakeKernelSymbolsSnapshot) IsGenerationValid(generation kallsyms.Generation) bool {
	return s.validGenerations[generation]
}

func (s *fakeKernelSymbolsSnapshot) ResolveAddress(address libpf.Address) (kallsyms.AddressResolution, bool) {
	s.resolveCount++
	resolution, ok := s.resolutions[address]
	return resolution, ok
}

func TestNewConfiguresFrameCacheSize(t *testing.T) {
	pm, err := New(t.Context(), interpreterconfig.NoInterpreters(), time.Hour, time.Hour,
		&testEbpfHandler{}, nil, nil, nil, nil, 1, false, libpf.Set[string]{})
	require.NoError(t, err)

	pm.frameCache.Add(frameCacheKey{data: [3]uint64{1}}, frameCacheValue{})
	pm.frameCache.Add(frameCacheKey{data: [3]uint64{2}}, frameCacheValue{})
	require.Equal(t, 1, pm.frameCache.Len())
}

func TestKernelFramesUseSharedFrameCache(t *testing.T) {
	frameCache, err := lru.New[frameCacheKey, frameCacheValue](1024, hashFrameCacheKey)
	require.NoError(t, err)

	const address = libpf.Address(0x1234)
	const generation = kallsyms.Generation(3)
	snapshot := &fakeKernelSymbolsSnapshot{
		validGenerations: map[kallsyms.Generation]bool{generation: true},
		resolutions: map[libpf.Address]kallsyms.AddressResolution{
			address: {
				Source:     kallsyms.SymbolSourceBPF,
				Generation: generation,
				BPFName:    "bpf_func",
				BPFOffset:  12,
			},
		},
	}
	capture := &traceCapture{}
	pm := &ProcessManager{
		frameCache:    frameCache,
		kernelSymbols: fakeKernelSymbols{snapshot: snapshot},
		traceReporter: capture,
	}

	for range 2 {
		pm.HandleTrace(&libpf.EbpfTrace{
			NumKernelFrames: 1,
			FrameData:       []uint64{uint64(address)},
		})
	}

	require.Len(t, capture.traces, 2)
	require.Len(t, capture.traces[0].Frames, 1)
	frame := capture.traces[0].Frames[0].Value()
	assert.Equal(t, libpf.KernelFrame, frame.Type)
	assert.Equal(t, "bpf_func", frame.FunctionName.String())
	assert.Equal(t, libpf.AddressOrLineno(12), frame.AddressOrLineno)

	assert.Equal(t, 1, snapshot.resolveCount)
	assert.Equal(t, uint64(1), pm.frameCacheMiss.Load())
	assert.Equal(t, uint64(1), pm.frameCacheHit.Load())
}

func TestKernelFrameCacheIgnoresInvalidEntries(t *testing.T) {
	frameCache, err := lru.New[frameCacheKey, frameCacheValue](1024, hashFrameCacheKey)
	require.NoError(t, err)

	const address = libpf.Address(0x1234)
	const staleGeneration = kallsyms.Generation(2)
	const currentGeneration = kallsyms.Generation(3)
	cachedFrame := unique.Make(libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0,
		FunctionName:    libpf.Intern("cached"),
	})
	frameCache.Add(kernelFrameCacheKey(address), frameCacheValue{
		frames:           libpf.Frames{cachedFrame},
		kernelGeneration: staleGeneration,
	})

	snapshot := &fakeKernelSymbolsSnapshot{
		validGenerations: map[kallsyms.Generation]bool{currentGeneration: true},
		resolutions: map[libpf.Address]kallsyms.AddressResolution{
			address: {
				Source:     kallsyms.SymbolSourceBPF,
				Generation: currentGeneration,
				BPFName:    "fresh",
				BPFOffset:  8,
			},
		},
	}
	capture := &traceCapture{}
	pm := &ProcessManager{
		frameCache:    frameCache,
		kernelSymbols: fakeKernelSymbols{snapshot: snapshot},
		traceReporter: capture,
	}

	pm.HandleTrace(&libpf.EbpfTrace{
		NumKernelFrames: 1,
		FrameData:       []uint64{uint64(address)},
	})

	require.Len(t, capture.traces, 1)
	require.Len(t, capture.traces[0].Frames, 1)
	if capture.traces[0].Frames[0] == cachedFrame {
		t.Fatalf("expected stale cache entry to be ignored")
	}
	assert.Equal(t, "fresh", capture.traces[0].Frames[0].Value().FunctionName.String())
	assert.Equal(t, 1, snapshot.resolveCount)
	assert.Equal(t, uint64(1), pm.frameCacheMiss.Load())
	assert.Equal(t, uint64(0), pm.frameCacheHit.Load())
}

func TestFrameCacheCrossProcessPollution(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux procfs")
	}

	exec, err := os.Executable()
	require.NoError(t, err)

	pc, _, _, ok := runtime.Caller(0)
	require.True(t, ok)

	goPID := libpf.PID(1000)
	catPID := libpf.PID(2000)

	goHostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)
	catHostFileID, err := host.FileIDFromBytes(
		[]byte{0xCA, 0x7C, 0xA7, 0xCA, 0x7C, 0xA7, 0xCA, 0x7C})
	require.NoError(t, err)
	libcHostFileID, err := host.FileIDFromBytes(
		[]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	require.NoError(t, err)

	realPID := libpf.PID(os.Getpid())
	pid := process.New(realPID, realPID)
	elfRef := pfelf.NewReference(exec, pid)
	loaderInfo := interpreter.NewLoaderInfo(goHostFileID, elfRef)
	rm := remotememory.NewProcessVirtualMemory(realPID)

	goData, err := golang.GetLoader(golang.Config{})(nil, loaderInfo)
	require.NoError(t, err)
	goInstance, err := goData.Attach(nil, realPID, 0x0, rm)
	require.NoError(t, err)

	goODID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}

	frameCache, err := lru.New[frameCacheKey, frameCacheValue](1024, hashFrameCacheKey)
	require.NoError(t, err)

	goMappings := []Mapping{
		{FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:   libpf.NewFileID(uint64(goHostFileID), 0),
				FileName: libpf.Intern("go-binary"),
			}),
			Start: 0,
			End:   0xFFFFFFF,
		})},
		{FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:   libpf.NewFileID(uint64(libcHostFileID), 0),
				FileName: libpf.Intern("libc.so.6"),
			}),
			Start: 0,
			End:   0xFFFFFFF,
		})},
	}
	slices.SortFunc(goMappings, compareMapping)

	catMappings := []Mapping{
		{FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:   libpf.NewFileID(uint64(catHostFileID), 0),
				FileName: libpf.Intern("cat"),
			}),
			Start: 0,
			End:   0xFFFFFFF,
		})},
		{FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:   libpf.NewFileID(uint64(libcHostFileID), 0),
				FileName: libpf.Intern("libc.so.6"),
			}),
			Start: 0,
			End:   0xFFFFFFF,
		})},
	}
	slices.SortFunc(catMappings, compareMapping)

	capture := &traceCapture{}
	pm := &ProcessManager{
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			goPID: {goODID: goInstance},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			goPID:  {mappings: goMappings},
			catPID: {mappings: catMappings},
		},
		frameCache:    frameCache,
		traceReporter: capture,
	}

	libcFrame := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, uint64(pc))
	libcFrame[1] = uint64(libcHostFileID)

	pm.HandleTrace(&libpf.EbpfTrace{
		PID:       goPID,
		TID:       goPID,
		NumFrames: 1,
		FrameData: libcFrame,
	})

	require.Len(t, capture.traces, 1)
	goTrace := capture.traces[0]
	require.NotEmpty(t, goTrace.Frames)

	goFrame := goTrace.Frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, goFrame.Type)
	assert.Equal(t, "", goFrame.FunctionName.String())

	pm.HandleTrace(&libpf.EbpfTrace{
		PID:       catPID,
		TID:       catPID,
		NumFrames: 1,
		FrameData: libcFrame,
	})

	require.Len(t, capture.traces, 2)
	catTrace := capture.traces[1]
	require.NotEmpty(t, catTrace.Frames)

	catFrame := catTrace.Frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, catFrame.Type)
	assert.Equal(t, "", catFrame.FunctionName.String())
}

func TestFrameCacheSharesNativeFallbackFramesAcrossProcesses(t *testing.T) {
	firstPID := libpf.PID(1000)
	secondPID := libpf.PID(2000)
	fileID, err := host.FileIDFromBytes(
		[]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	require.NoError(t, err)

	frameCache, err := lru.New[frameCacheKey, frameCacheValue](1024, hashFrameCacheKey)
	require.NoError(t, err)

	mappings := []Mapping{
		{FrameMapping: libpf.NewFrameMapping(libpf.FrameMappingData{
			File: libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
				FileID:   libpf.NewFileID(uint64(fileID), 0),
				FileName: libpf.Intern("libc.so.6"),
			}),
			Start: 0,
			End:   0xFFFFFFF,
		})},
	}
	capture := &traceCapture{}
	pm := &ProcessManager{
		pidToProcessInfo: map[libpf.PID]*processInfo{
			firstPID:  {mappings: mappings},
			secondPID: {mappings: mappings},
		},
		frameCache:    frameCache,
		traceReporter: capture,
	}

	nativeFrame := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, 0x222a0)
	nativeFrame[1] = uint64(fileID)

	pm.HandleTrace(&libpf.EbpfTrace{
		PID:       firstPID,
		TID:       firstPID,
		NumFrames: 1,
		FrameData: nativeFrame,
	})
	pm.HandleTrace(&libpf.EbpfTrace{
		PID:       secondPID,
		TID:       secondPID,
		NumFrames: 1,
		FrameData: nativeFrame,
	})

	require.Len(t, capture.traces, 2)

	require.NotEmpty(t, capture.traces[0].Frames)
	frame0 := capture.traces[0].Frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, frame0.Type)
	assert.Equal(t, "", frame0.FunctionName.String())

	require.NotEmpty(t, capture.traces[1].Frames)
	frame1 := capture.traces[1].Frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, frame1.Type)
	assert.Equal(t, "", frame1.FunctionName.String())

	assert.Equal(t, uint64(1), pm.frameCacheMiss.Load())
	assert.Equal(t, uint64(1), pm.frameCacheHit.Load())
}
