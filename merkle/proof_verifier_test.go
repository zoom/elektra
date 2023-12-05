package merkle

import (
	"testing"

	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/stretchr/testify/require"
)

func TestVerifyExtensionProof(t *testing.T) {
	cfg, err := newConfigForTest(IdentityHasher{}, 1, 1, 1)
	require.NoError(t, err)
	eng := NewInMemoryStorageEngine(cfg)

	ctx := NewLoggerContextTodoForTesting(t)
	var tr Transaction = nil

	l := NewLBBMT(eng)

	h0 := []byte{0x00}
	h1 := []byte{0x01}
	h2 := []byte{0x02}
	h3 := []byte{0x03}
	h4 := []byte{0x04}
	require.NoError(t, l.Push(ctx, tr, h0))
	r0, err := l.Root(ctx, tr)
	require.NoError(t, err)
	require.NoError(t, l.Push(ctx, tr, h1))
	r1, err := l.Root(ctx, tr)
	require.NoError(t, err)
	require.NoError(t, l.Push(ctx, tr, h2))
	r2, err := l.Root(ctx, tr)
	require.NoError(t, err)
	require.NoError(t, l.Push(ctx, tr, h3))
	r3, err := l.Root(ctx, tr)
	require.NoError(t, err)
	require.NoError(t, l.Push(ctx, tr, h4))
	r4, err := l.Root(ctx, tr)
	require.NoError(t, err)
	var prf *MerkleExtensionProof

	prf = genproof(ctx, tr, t, l, consistencyProofIndices(1, 5))
	require.NoError(t, verifyExtensionProof(prf, 1, 5, r0, r4))

	prf = genproof(ctx, tr, t, l, consistencyProofIndices(2, 5))
	require.NoError(t, verifyExtensionProof(prf, 2, 5, r1, r4))

	prf = genproof(ctx, tr, t, l, consistencyProofIndices(3, 5))
	require.NoError(t, verifyExtensionProof(prf, 3, 5, r2, r4))

	prf = genproof(ctx, tr, t, l, consistencyProofIndices(4, 5))
	require.NoError(t, verifyExtensionProof(prf, 4, 5, r3, r4))

	prf = genproof(ctx, tr, t, l, consistencyProofIndices(5, 5))
	require.NoError(t, verifyExtensionProof(prf, 5, 5, r4, r4))
}

func genproof(ctx logger.ContextInterface, tr Transaction, t *testing.T, l *LBBMT, idxs []int) *MerkleExtensionProof {
	var prf [][]byte
	for _, idx := range idxs {
		v, err := l.storage.ArrayGet(ctx, tr, idx)
		require.NoError(t, err)
		prf = append(prf, v)
	}
	return &MerkleExtensionProof{HistoryTreeNodeHashes: prf}
}
