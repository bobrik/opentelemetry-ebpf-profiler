package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/process"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type TestInstance struct {
	interpreter.InstanceStubs
	info libc.LibcInfo
}

func (ti *TestInstance) UpdateLibcInfo(handler interpreter.EbpfHandler, pid libpf.PID, info libc.LibcInfo) error {
	ti.info = info
	return nil
}

func (ti *TestInstance) Detach(handler interpreter.EbpfHandler, pid libpf.PID) error {
	return nil
}

type testInterpreterData struct {
	attach func(interpreter.EbpfHandler, libpf.PID, libpf.Address, remotememory.RemoteMemory) (
		interpreter.Instance, error)
}

func (td *testInterpreterData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	return td.attach(ebpf, pid, bias, rm)
}

func (td *testInterpreterData) Unload(interpreter.EbpfHandler) {}

type testEbpfHandler struct {
	markInterpreterPIDErr   error
	unmarkInterpreterPIDErr error
	markInterpreterPIDs     []libpf.PID
	unmarkInterpreterPIDs   []libpf.PID
}

func (te *testEbpfHandler) MarkInterpreterPID(pid libpf.PID) error {
	te.markInterpreterPIDs = append(te.markInterpreterPIDs, pid)
	return te.markInterpreterPIDErr
}

func (te *testEbpfHandler) UnmarkInterpreterPID(pid libpf.PID) error {
	te.unmarkInterpreterPIDs = append(te.unmarkInterpreterPIDs, pid)
	return te.unmarkInterpreterPIDErr
}

func (te *testEbpfHandler) UpdateInterpreterOffsets(uint16, host.FileID, []util.Range) error {
	return nil
}

func (te *testEbpfHandler) UpdateProcData(libpf.InterpreterType, libpf.PID, unsafe.Pointer) error {
	return nil
}

func (te *testEbpfHandler) DeleteProcData(libpf.InterpreterType, libpf.PID) error {
	return nil
}

func (te *testEbpfHandler) UpdatePidInterpreterMapping(
	libpf.PID, lpm.Prefix, uint8, host.FileID, uint64,
) error {
	return nil
}

func (te *testEbpfHandler) DeletePidInterpreterMapping(libpf.PID, lpm.Prefix) error {
	return nil
}

func (te *testEbpfHandler) RemoveReportedPID(libpf.PID) {}

func (te *testEbpfHandler) UpdateUnwindInfo(uint16, sdtypes.UnwindInfo) error {
	return nil
}

func (te *testEbpfHandler) UpdateExeIDToStackDeltas(
	host.FileID, []pmebpf.StackDeltaEBPF,
) (uint16, error) {
	return 0, nil
}

func (te *testEbpfHandler) DeleteExeIDToStackDeltas(host.FileID, uint16) error {
	return nil
}

func (te *testEbpfHandler) UpdateStackDeltaPages(host.FileID, []uint16, uint16, uint64) error {
	return nil
}

func (te *testEbpfHandler) DeleteStackDeltaPage(host.FileID, uint64) error {
	return nil
}

func (te *testEbpfHandler) UpdatePidPageMappingInfo(libpf.PID, lpm.Prefix, uint64, uint64) error {
	return nil
}

func (te *testEbpfHandler) DeletePidPageMappingInfo(libpf.PID, []lpm.Prefix) (uint64, error) {
	return 0, nil
}

func (te *testEbpfHandler) CollectMetrics() []metrics.Metric {
	return nil
}

func (te *testEbpfHandler) SupportsLPMTrieBatchOperations() bool {
	return false
}

func TestAssignLibcInfoMergesLibcInfo(t *testing.T) {
	assert := assert.New(t)

	pid := libpf.PID(1)
	odid := util.OnDiskFileIdentifier{
		DeviceID: 1,
		InodeNum: 1,
	}

	interp := TestInstance{}

	pm := ProcessManager{
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				odid: &interp,
			},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{
			pid: {},
		},
	}

	libcInfoWithTSD := libc.LibcInfo{
		TSDInfo: libc.TSDInfo{
			Offset:     8,
			Multiplier: 8,
			Indirect:   0,
		},
		DTVInfo: libc.DTVInfo{},
	}
	pm.assignLibcInfo(pid, &libcInfoWithTSD)

	assert.Equal(libcInfoWithTSD, interp.info)

	libcInfoWithDTV := libc.LibcInfo{
		TSDInfo: libc.TSDInfo{},
		DTVInfo: libc.DTVInfo{
			Offset:     -8,
			Multiplier: 16,
		},
	}

	merged := libcInfoWithTSD
	merged.Merge(libcInfoWithDTV)

	pm.assignLibcInfo(pid, &libcInfoWithDTV)
	assert.Equal(merged, interp.info)
	assert.Equal(libcInfoWithTSD.TSDInfo, interp.info.TSDInfo)
	assert.Equal(libcInfoWithDTV.DTVInfo, interp.info.DTVInfo)

	pm.assignLibcInfo(pid, &merged)
	assert.Equal(merged, interp.info)
	assert.Equal(libcInfoWithTSD.TSDInfo, interp.info.TSDInfo)
	assert.Equal(libcInfoWithDTV.DTVInfo, interp.info.DTVInfo)
}

func TestHandleNewInterpreterMarksPIDBeforeAttach(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:             ebpf,
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			require.Equal([]libpf.PID{pid}, ebpf.markInterpreterPIDs)
			require.Empty(ebpf.unmarkInterpreterPIDs)
			return &TestInstance{}, nil
		},
	}

	err := pm.handleNewInterpreter(process.New(pid, pid), 0, oid, data)
	require.NoError(err)
	require.Contains(pm.interpreters[pid], oid)
	require.Equal([]libpf.PID{pid}, ebpf.markInterpreterPIDs)
	require.Empty(ebpf.unmarkInterpreterPIDs)
}

func TestHandleNewInterpreterRollsBackMarkerOnAttachFailure(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	attachErr := errors.New("attach failed")
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:             ebpf,
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			require.Equal([]libpf.PID{pid}, ebpf.markInterpreterPIDs)
			return nil, attachErr
		},
	}

	err := pm.handleNewInterpreter(process.New(pid, pid), 0, oid, data)
	require.ErrorIs(err, attachErr)
	require.NotContains(pm.interpreters, pid)
	require.Equal([]libpf.PID{pid}, ebpf.markInterpreterPIDs)
	require.Equal([]libpf.PID{pid}, ebpf.unmarkInterpreterPIDs)
}

func TestHandleNewInterpreterDoesNotAttachOnMarkerFailure(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	markerErr := errors.New("marker failed")
	ebpf := &testEbpfHandler{markInterpreterPIDErr: markerErr}
	pm := &ProcessManager{
		ebpf:             ebpf,
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	attachCalled := false
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			attachCalled = true
			return &TestInstance{}, nil
		},
	}

	err := pm.handleNewInterpreter(process.New(pid, pid), 0, oid, data)
	require.ErrorIs(err, markerErr)
	require.False(attachCalled)
	require.NotContains(pm.interpreters, pid)
	require.Equal([]libpf.PID{pid}, ebpf.markInterpreterPIDs)
	require.Empty(ebpf.unmarkInterpreterPIDs)
}

func TestHandleNewInterpreterDoesNotRemarkExistingInterpreterPID(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oldOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}
	newOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf: ebpf,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oldOID: &TestInstance{}},
		},
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
	}
	data := &testInterpreterData{
		attach: func(interpreter.EbpfHandler, libpf.PID, libpf.Address,
			remotememory.RemoteMemory,
		) (interpreter.Instance, error) {
			require.Empty(ebpf.markInterpreterPIDs)
			return &TestInstance{}, nil
		},
	}

	err := pm.handleNewInterpreter(process.New(pid, pid), 0, newOID, data)
	require.NoError(err)
	require.Contains(pm.interpreters[pid], oldOID)
	require.Contains(pm.interpreters[pid], newOID)
	require.Empty(ebpf.markInterpreterPIDs)
	require.Empty(ebpf.unmarkInterpreterPIDs)
}

func TestProcessRemovedInterpretersDeletesMarkerForLastInterpreter(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	oid := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {oid: &TestInstance{}},
		},
	}

	pm.processRemovedInterpreters(pid, libpf.Set[util.OnDiskFileIdentifier]{})
	require.NotContains(pm.interpreters, pid)
	require.Equal([]libpf.PID{pid}, ebpf.unmarkInterpreterPIDs)
}

func TestProcessRemovedInterpretersKeepsMarkerWhenInterpreterRemains(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	keptOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 1}
	removedOID := util.OnDiskFileIdentifier{DeviceID: 1, InodeNum: 2}
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:                     ebpf,
		interpreterTracerEnabled: true,
		interpreters: map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance{
			pid: {
				keptOID:    &TestInstance{},
				removedOID: &TestInstance{},
			},
		},
	}

	pm.processRemovedInterpreters(pid, libpf.Set[util.OnDiskFileIdentifier]{keptOID: libpf.Void{}})
	require.Contains(pm.interpreters[pid], keptOID)
	require.NotContains(pm.interpreters[pid], removedOID)
	require.Empty(ebpf.unmarkInterpreterPIDs)
}

func TestProcessPIDExitDeletesInterpreterPIDMarker(t *testing.T) {
	require := require.New(t)
	pid := libpf.PID(123)
	ebpf := &testEbpfHandler{}
	pm := &ProcessManager{
		ebpf:             ebpf,
		interpreters:     make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance),
		pidToProcessInfo: map[libpf.PID]*processInfo{pid: {}},
		exitEvents:       make(map[libpf.PID]times.KTime),
	}

	pm.processPIDExit(pid)
	require.Equal([]libpf.PID{pid}, ebpf.unmarkInterpreterPIDs)
}
