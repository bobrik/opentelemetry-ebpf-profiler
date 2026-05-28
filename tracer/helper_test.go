package tracer

import (
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestReadCPURange(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected []int
	}{
		"mixed": {
			input:    "0,3-6,8-11",
			expected: []int{0, 3, 4, 5, 6, 8, 9, 10, 11},
		},
		"all": {
			input:    "0-7",
			expected: []int{0, 1, 2, 3, 4, 5, 6, 7},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := readCPURange(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestDisableVMAHelperCalls(t *testing.T) {
	findVMA := asm.FnFindVma.Call().WithSymbol("find_vma")
	getTask := asm.FnGetCurrentTaskBtf.Call()
	keep := asm.FnMapLookupElem.Call()

	coll := &cebpf.CollectionSpec{
		Programs: map[string]*cebpf.ProgramSpec{
			"prog": {
				Instructions: asm.Instructions{
					keep,
					findVMA,
					getTask,
				},
			},
		},
	}

	require.Equal(t, 2, disableVMAHelperCalls(coll))
	require.Equal(t, keep, coll.Programs["prog"].Instructions[0])
	require.Equal(t, asm.Mov.Imm(asm.R0, -int32(unix.ENOTSUP)).WithMetadata(findVMA.Metadata),
		coll.Programs["prog"].Instructions[1])
	require.Equal(t, asm.Mov.Imm(asm.R0, 0), coll.Programs["prog"].Instructions[2])
}
