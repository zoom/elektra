package merkle

import (
	"testing"

	"encoding/hex"

	"github.com/stretchr/testify/require"
)

func TestNewLBBMT(t *testing.T) {
	cfg, err := newConfigForTest(IdentityHasher{}, 1, 1, 1)
	require.NoError(t, err)
	eng := NewInMemoryStorageEngine(cfg)

	ctx := NewLoggerContextTodoForTesting(t)
	var tr Transaction = nil

	h := []byte{}
	l := NewLBBMT(eng)

	N, err := l.size(ctx, tr)
	require.NoError(t, err)
	require.Equal(t, N, 0)

	err = l.Push(ctx, tr, h)
	require.NoError(t, err)
	r, err := l.Root(ctx, tr)
	require.NoError(t, err)
	require.EqualValues(t, r, h)
}

func TestLBBMTHashing(t *testing.T) {
	cfg, err := newConfigForTest(IdentityHasher{}, 1, 1, 1)
	require.NoError(t, err)
	eng := NewInMemoryStorageEngine(cfg)

	ctx := NewLoggerContextTodoForTesting(t)
	var tr Transaction = nil

	l := NewLBBMT(eng)

	err = l.Push(ctx, tr, []byte{0x01})
	require.NoError(t, err)
	err = l.Push(ctx, tr, []byte{0x02})
	require.NoError(t, err)
	r, err := l.Root(ctx, tr)
	require.NoError(t, err)
	require.EqualValues(t, "a12871fee210fb8619291eaea194581cbd2531e4b23759d225f6806923f63222",
		hex.EncodeToString(r))
	err = l.Push(ctx, tr, []byte{0x03})
	require.NoError(t, err)
	r, err = l.Root(ctx, tr)
	require.NoError(t, err)
	require.EqualValues(t, "ebfa2f40eb7f95d4e7f5c51ecab4b7cd8bceed4facb77185c132949f88e958d3",
		hex.EncodeToString(r))
	err = l.Push(ctx, tr, []byte{0x04})
	require.NoError(t, err)
	r, err = l.Root(ctx, tr)
	require.NoError(t, err)
	require.EqualValues(t, "bed3d33a81026f7be93aefad44c5891c27fc8265aa15279a58e287744b7c7753",
		hex.EncodeToString(r))
	err = l.Push(ctx, tr, []byte{0x05})
	require.NoError(t, err)
	r, err = l.Root(ctx, tr)
	require.NoError(t, err)
	require.EqualValues(t, "a35f83263956472c7295a1e38d093b12a0e1843b7f998c843b2f3b3347c271d2",
		hex.EncodeToString(r))
}

func TestLBBMTisLeftChild(t *testing.T) {
	require.Equal(t, true, isLeftChild(16, 16))
	require.Equal(t, true, isLeftChild(17, 16))
	require.Equal(t, true, isLeftChild(9, 16))
	require.Equal(t, true, isLeftChild(7, 16))

	require.Equal(t, false, isLeftChild(18, 16))
	require.Equal(t, false, isLeftChild(11, 16))
	require.Equal(t, false, isLeftChild(29, 16))
	require.Equal(t, false, isLeftChild(23, 16))

	require.Equal(t, false, isLeftChild(8, 5))
	require.Equal(t, true, isLeftChild(8, 6))
}
