// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"unique"

	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

const kernelFrameCacheKeyMarker = ^uint64(0)

type kernelSymbols interface {
	Snapshot() kernelSymbolsSnapshot
}

type kernelSymbolsSnapshot interface {
	IsGenerationValid(kallsyms.Generation) bool
	ResolveAddress(libpf.Address) (kallsyms.AddressResolution, bool)
}

type kallsymsKernelSymbols struct {
	symbolizer *kallsyms.Symbolizer
}

func (s kallsymsKernelSymbols) Snapshot() kernelSymbolsSnapshot {
	return s.symbolizer.Snapshot()
}

type frameCacheValue struct {
	frames           libpf.Frames
	kernelGeneration kallsyms.Generation
}

func kernelFrameCacheKey(address libpf.Address) frameCacheKey {
	return frameCacheKey{
		data: [3]uint64{kernelFrameCacheKeyMarker, uint64(address)},
	}
}

func symbolizeBPFFrame(name string, offset uint) unique.Handle[libpf.Frame] {
	return unique.Make(libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: libpf.AddressOrLineno(offset),
		FunctionName:    libpf.Intern(name),
	})
}

func symbolizeKernelFrame(address libpf.Address, resolution kallsyms.AddressResolution) unique.Handle[libpf.Frame] {
	if resolution.Source == kallsyms.SymbolSourceBPF {
		return symbolizeBPFFrame(resolution.BPFName, resolution.BPFOffset)
	}

	frame := libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: libpf.AddressOrLineno(address - 1),
	}

	if kmod := resolution.Module; kmod != nil {
		frame.Mapping = kmod.Mapping()
		frame.AddressOrLineno -= libpf.AddressOrLineno(kmod.Start())
		if funcName, _, err := kmod.LookupSymbolByAddress(address); err == nil {
			frame.FunctionName = libpf.Intern(funcName)
		}
	}

	return unique.Make(frame)
}
