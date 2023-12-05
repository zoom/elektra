package storage

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/merkle"
	"github.com/mvkdcrypto/mvkd/demo/vrf"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"

	"github.com/stretchr/testify/require"
)

func newEngine(cfg merkle.Config) *MerkleStorageEngine {
	treeId := make([]byte, 16)
	_, err := cryptorand.Read(treeId)
	if err != nil {
		panic(err)
	}
	db, err := sqlx.Open("postgres", "user=foo dbname=merkle sslmode=disable")
	if err != nil {
		panic(err)
	}
	db.SetMaxOpenConns(1)
	return NewMerkleStorageEngine(db, cfg, treeId)
}

func NewLoggerContextTodoForTesting(t testing.TB) logger.ContextInterface {
	return logger.NewContext(context.TODO(), logger.NewTestLogger(t))
}

func ConstructStringValueContainer() interface{} {
	return ""
}

func newMerkleConfigForTest(e merkle.Encoder, logChildrenPerNode uint8, maxValuesPerLeaf int,
	keysByteLength int) (merkle.Config, error) {
	return merkle.NewConfig(e, logChildrenPerNode, maxValuesPerLeaf, keysByteLength,
		ConstructStringValueContainer, &merkle.IdentityVRF{})
}

func newMerkleConfigForTestWithVRF(e merkle.Encoder, logChildrenPerNode uint8,
	maxValuesPerLeaf int) (merkle.Config, error) {
	return merkle.NewConfig(e, logChildrenPerNode, maxValuesPerLeaf, 32,
		ConstructStringValueContainer, vrf.ECVRFP256SHA256TAI())
}

func irun(t testing.TB, eng *merkle.InMemoryStorageEngine, f func(tr *sqlx.Tx)) {
	f(nil)
}
func run(t testing.TB, eng *MerkleStorageEngine, f func(tr *sqlx.Tx)) {
	tx := eng.db.MustBegin()
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
		err := tx.Commit()
		if err != nil {
			panic(err)
		}
	}()
	f(tx)
}

func TestZbTreeInsertAtInternal(t *testing.T) {
	cfg, err := newMerkleConfigForTest(merkle.IdentityHasher{}, 1, 1, 1)
	require.NoError(t, err)

	kvps := []merkle.KeyValuePair{
		{Key: []byte{0b00000000}, Value: "alfa"},
		{Key: []byte{0b00010000}, Value: "brav"},
		{Key: []byte{0b00100000}, Value: "char"},
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	eng := newEngine(cfg)
	tree, err := merkle.NewTree(cfg, defaultStep, eng, merkle.RootVersionV1)
	require.NoError(t, err)

	run(t, eng, func(tr *sqlx.Tx) {
		s, _, err := tree.Build(logctx, tr, kvps, nil, false)
		require.NoError(t, err)
		require.Equal(t, s, merkle.Seqno(1))
	})
}

func TestZbShape(t *testing.T) {
	batchsize := 1
	cfg, err := newMerkleConfigForTest(merkle.IdentityHasher{}, 1, batchsize, 1)
	require.NoError(t, err)

	kvps := []merkle.KeyValuePair{
		{Key: []byte{0b00000000}, Value: "alfa"},
		{Key: []byte{0b01000000}, Value: "brav"},
		{Key: []byte{0b00010000}, Value: "char"},
		{Key: []byte{0b00110000}, Value: "echo"},
		{Key: []byte{0b00100000}, Value: "foxt"},
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	eng := newEngine(cfg)
	tree, err := merkle.NewTree(cfg, defaultStep, eng, merkle.RootVersionV1)
	require.NoError(t, err)

	run(t, eng, func(tr *sqlx.Tx) {
		_, _, err = tree.Build(logctx, tr, kvps, nil, false)
		require.NoError(t, err)

		p := cfg.GetRootPosition()
		p = cfg.GetChild(p, 0)
		p = cfg.GetChild(p, 0)
		p = cfg.GetChild(p, 0)
		pairs, err := eng.LookupPairsUnderPosition(logctx, tr, 1, 1, p)
		require.NoError(t, err)
		var keys [][]byte
		for _, pair := range pairs {
			keys = append(keys, []byte(pair.Key))
		}
		require.Equal(t, [][]byte{[]byte{0}, []byte{0b0001_0000}}, keys)

	})

}

func TestZbTreeStructureBasic(t *testing.T) {
	batchsize := 1
	cfg, err := newMerkleConfigForTest(merkle.IdentityHasher{}, 1, batchsize, 1)
	require.NoError(t, err)

	kvps := []merkle.KeyValuePair{
		{Key: []byte{0b00000000}, Value: "alfa"},
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	i := newEngine(cfg)
	tree, err := merkle.NewTree(cfg, defaultStep, i, merkle.RootVersionV1)
	require.NoError(t, err)

	run(t, i, func(tr *sqlx.Tx) {
		s, hthash, err := tree.Build(logctx, tr, kvps, nil, false)
		require.NoError(t, err)
		require.Equal(t, s, merkle.Seqno(1))

		_, rootmd, _, err := tree.GetLatestRoot(logctx, tr)
		require.NoError(t, err)
		require.Equal(t, rootmd.Seqno, merkle.Seqno(1))

		ok, val, _, err := tree.QueryKey(logctx, tr, 1, kvps[0].Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, val, "alfa")

		verifier := merkle.NewMerkleProofVerifier(cfg)
		for _, kvp := range kvps {
			ok, ret, proof, err := tree.QueryKey(logctx, tr, 1, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, ret, kvp.Value)
			require.NoError(t, verifier.VerifyInclusionProof(logctx, kvp, &proof, hthash))
		}
	})
}

func TestZbTreeStructure(t *testing.T) {
	batchsize := 1
	cfg, err := newMerkleConfigForTest(merkle.IdentityHasher{}, 1, batchsize, 1)
	require.NoError(t, err)

	kvps := []merkle.KeyValuePair{
		{Key: []byte{0b00000000}, Value: "alfa"},
		{Key: []byte{0b01000000}, Value: "brav"},
		{Key: []byte{0b00010000}, Value: "char"},
		{Key: []byte{0b00110000}, Value: "echo"},
		{Key: []byte{0b00100000}, Value: "foxt"},
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	i := newEngine(cfg)
	tree, err := merkle.NewTree(cfg, defaultStep, i, merkle.RootVersionV1)
	require.NoError(t, err)

	run(t, i, func(tr *sqlx.Tx) {
		s, hthash, err := tree.Build(logctx, tr, kvps, nil, false)
		require.NoError(t, err)
		require.Equal(t, s, merkle.Seqno(1))

		ok, val, _, err := tree.QueryKey(logctx, tr, 1, kvps[0].Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, val, "alfa")

		verifier := merkle.NewMerkleProofVerifier(cfg)
		for _, kvp := range kvps {
			ok, ret, proof, err := tree.QueryKey(logctx, tr, 1, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, ret, kvp.Value)
			require.NoError(t, verifier.VerifyInclusionProof(logctx, kvp, &proof, hthash))
		}

		k := []byte{0b01100000}
		ok, _, proof, err := tree.QueryKey(logctx, tr, 1, k)
		require.NoError(t, err)
		require.False(t, ok)
		require.NoError(t, verifier.VerifyExclusionProof(logctx, k, &proof, hthash))
	})
}

func TestExtensionProofsHappy(t *testing.T) {
	cfg, err := newMerkleConfigForTest(merkle.SHA512_256Encoder{}, 1, 1, 3)
	require.NoError(t, err)

	// make test deterministic
	rand.Seed(1)

	i := newEngine(cfg)
	tree, err := merkle.NewTree(cfg, 2, i, merkle.RootVersionV1)
	require.NoError(t, err)

	run(t, i, func(tr *sqlx.Tx) {
		htrootHashes := make(map[merkle.Seqno][]byte)

		maxSeqno := merkle.Seqno(100) // 100

		keys, _, err := merkle.MakeRandomKeysForTesting(uint(cfg.KeysByteLength), int(maxSeqno), 0)
		require.NoError(t, err)
		kvps, err := merkle.MakeRandomKVPFromKeysForTesting(keys)

		// build a bunch of tree versions:
		for j := merkle.Seqno(1); j <= maxSeqno; j++ {
			addOnsHash := []byte(nil)
			// put a random AddOnsHash in half of the tree roots
			if rand.Intn(2) == 1 {
				buf := make([]byte, 32)
				rand.Read(buf)
				addOnsHash = []byte(buf)
			}
			require.NoError(t, err)
			kvp := []merkle.KeyValuePair{kvps[int(j)-1]}
			_, hthash, err := tree.Build(NewLoggerContextTodoForTesting(t), tr, kvp, addOnsHash, false)
			htrootHashes[j] = hthash
			require.NoError(t, err)
		}

		verifier := merkle.NewMerkleProofVerifier(cfg)

		numTests := 50
		for j := 0; j < numTests; j++ {
			//startSeqno := Seqno(rand.Intn(int(maxSeqno)-1) + 1)
			//endSeqno := Seqno(rand.Intn(int(maxSeqno)-1) + 1)
			startSeqno := maxSeqno
			endSeqno := maxSeqno

			if startSeqno > endSeqno {
				startSeqno, endSeqno = endSeqno, startSeqno
			}

			eProof, err := tree.GetExtensionProof(NewLoggerContextTodoForTesting(t), tr, startSeqno, endSeqno)
			require.NoError(t, err)

			err = verifier.VerifyExtensionProof(NewLoggerContextTodoForTesting(t), &eProof, startSeqno, htrootHashes[startSeqno], endSeqno, htrootHashes[endSeqno])
			require.NoError(t, err)
		}

		// Test the special cases start == end and start == end - 1
		startSeqno := merkle.Seqno(rand.Intn(int(maxSeqno)-1) + 1)
		endSeqno := startSeqno

		eProof, err := tree.GetExtensionProof(NewLoggerContextTodoForTesting(t), tr, startSeqno, endSeqno)
		require.NoError(t, err)

		err = verifier.VerifyExtensionProof(NewLoggerContextTodoForTesting(t), &eProof, startSeqno, htrootHashes[startSeqno], endSeqno, htrootHashes[endSeqno])
		require.NoError(t, err)

		endSeqno = startSeqno + 1

		eProof, err = tree.GetExtensionProof(NewLoggerContextTodoForTesting(t), tr, startSeqno, endSeqno)
		require.NoError(t, err)

		err = verifier.VerifyExtensionProof(NewLoggerContextTodoForTesting(t), &eProof, startSeqno, htrootHashes[startSeqno], endSeqno, htrootHashes[endSeqno])
		require.NoError(t, err)
	})

}

func TestZbTreeStructureLongKeys(t *testing.T) {
	cfg, err := newMerkleConfigForTest(merkle.IdentityHasher{}, 1, 1, 32)
	require.NoError(t, err)

	kvps := []merkle.KeyValuePair{
		{Key: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Value: "alfa"},
		{Key: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Value: "beta"},
		//{Key: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		//	0, 0, 0, 0, 0, 0, 0, 0, 232, 0, 0, 0, 0, 0, 0, 0}, Value: "gamma"},
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	i := newEngine(cfg)
	tree, err := merkle.NewTree(cfg, defaultStep, i, merkle.RootVersionV1)
	require.NoError(t, err)

	run(t, i, func(tr *sqlx.Tx) {

		s, hthash, err := tree.Build(logctx, tr, kvps, nil, false)
		require.NoError(t, err)
		require.Equal(t, s, merkle.Seqno(1))

		ok, val, _, err := tree.QueryKey(logctx, tr, 1, kvps[0].Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, val, "alfa")

		verifier := merkle.NewMerkleProofVerifier(cfg)
		for _, kvp := range kvps {
			ok, ret, proof, err := tree.QueryKey(logctx, tr, 1, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, ret, kvp.Value)
			require.NoError(t, verifier.VerifyInclusionProof(logctx, kvp, &proof, hthash))
		}

	})
}

// // Test historical proofs
func TestHonestMerkleProofsVerifySuccesfullyLargeTree(t *testing.T) {
	cfg1, err := newMerkleConfigForTest(merkle.IdentityHasher{}, 1, 1, 32)
	require.NoError(t, err)

	// Make test deterministic.
	rand.Seed(1)

	tests := []struct {
		cfg         merkle.Config
		step        int
		numIncPairs int
		numExcPairs int
		rootVersion merkle.RootVersion
	}{
		{cfg1, 1, 200, 20, merkle.RootVersionV1},
		// {cfg2, 1, 200, 20, merkle.RootVersionV1},
	}

	ctx := NewLoggerContextTodoForTesting(t)

	for _, test := range tests {
		t.Run(fmt.Sprintf("%v bits %v values per leaf tree", test.cfg.BitsPerIndex, test.cfg.MaxValuesPerLeaf), func(t *testing.T) {
			i := newEngine(test.cfg)
			tree, err := merkle.NewTree(test.cfg, test.step, i, test.rootVersion)
			require.NoError(t, err)

			run(t, i, func(tr *sqlx.Tx) {
				verifier := merkle.NewMerkleProofVerifier(test.cfg)

				keys, keysNotInTree, err := merkle.MakeRandomKeysForTesting(uint(test.cfg.KeysByteLength), test.numIncPairs, test.numExcPairs)
				require.NoError(t, err)
				keys2, _, err := merkle.MakeRandomKeysForTesting(uint(test.cfg.KeysByteLength), test.numIncPairs, test.numExcPairs)
				require.NoError(t, err)

				kvp1, err := merkle.MakeRandomKVPFromKeysForTesting(keys)
				require.NoError(t, err)
				kvp2, err := merkle.MakeRandomKVPFromKeysForTesting(keys2)
				require.NoError(t, err)

				s1, rootHash1, err := tree.Build(ctx, tr, kvp1, nil, false)
				require.NoError(t, err)
				require.EqualValues(t, 1, s1)

				for i, key := range keys {
					ok, kvpRet, proof, err := tree.QueryKey(ctx, tr, 1, key)
					require.NoError(t, err)
					require.True(t, ok)
					require.Equal(t, kvp1[i].Value, kvpRet)
					err = verifier.VerifyInclusionProof(ctx, kvp1[i], &proof, rootHash1)
					require.NoErrorf(t, err, "Error verifying proof for key %v: %v", key, err)
				}
				for _, key := range keysNotInTree {
					ok, _, proof, err := tree.QueryKey(ctx, tr, 1, key)
					require.NoError(t, err)
					require.False(t, ok)
					require.NoError(t, verifier.VerifyExclusionProof(ctx, key, &proof, rootHash1))
				}

				s2, rootHash2, err := tree.Build(ctx, tr, kvp2, nil, false)
				require.NoError(t, err)
				require.EqualValues(t, 2, s2)

				for i, key := range keys2 {
					ok, kvpRet, proof, err := tree.QueryKey(ctx, tr, 2, key)
					require.NoError(t, err)
					require.True(t, ok)
					require.Equal(t, kvp2[i].Value, kvpRet)
					require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp2[i], &proof, rootHash2))
				}
				for i, key := range keys {
					ok, kvpRet, proof, err := tree.QueryKey(ctx, tr, 2, key)
					require.NoError(t, err)
					require.True(t, ok)
					require.Equal(t, kvp1[i].Value, kvpRet)
					require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp1[i], &proof, rootHash2))

					ok, kvpRet, proof, err = tree.QueryKey(ctx, tr, 1, key)
					require.NoError(t, err)
					require.True(t, ok)
					require.Equal(t, kvp1[i].Value, kvpRet)
					require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp1[i], &proof, rootHash1))
				}

				for _, key := range keysNotInTree {
					ok, _, proof, err := tree.QueryKey(ctx, tr, 2, key)
					require.NoError(t, err)
					require.False(t, ok)
					require.NoError(t, verifier.VerifyExclusionProof(ctx, key, &proof, rootHash2))

					ok, _, proof, err = tree.QueryKey(ctx, tr, 1, key)
					require.NoError(t, err)
					require.False(t, ok)
					require.NoError(t, verifier.VerifyExclusionProof(ctx, key, &proof, rootHash1))
				}
			})
		})
	}
}

func hexDecode(s string) []byte {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return decoded
}

// Add 2, Add 2, Rotate, Add 2, Add 2, Rotate, Add 2, Add 2
func TestRotateSimple(t *testing.T) {
	cfg, err := newMerkleConfigForTestWithVRF(merkle.SHA512_256Encoder{}, 1, 1)
	require.NoError(t, err)

	kvps1 := []merkle.KeyValuePair{
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000000000"), Value: "alfa"},
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000000010"), Value: "brav"},
	}
	kvps2 := []merkle.KeyValuePair{
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000000100"), Value: "char"},
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000001000"), Value: "delt"},
	}
	kvps3 := []merkle.KeyValuePair{
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000010000"), Value: "echo"},
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000100000"), Value: "foxt"},
	}
	defaultStep := 2
	ctx := NewLoggerContextTodoForTesting(t)

	i := newEngine(cfg)
	tree, err := merkle.NewTree(cfg, defaultStep, i, merkle.RootVersionV1)
	require.NoError(t, err)

	run(t, i, func(tr *sqlx.Tx) {
		verifier := merkle.NewMerkleProofVerifier(cfg)

		// STAGE 1
		_, root1, err := tree.Build(ctx, tr, kvps1, nil, false)
		require.NoError(t, err)

		for _, kvp := range kvps1 {
			ok, ret, proof, err := tree.QueryKey(ctx, tr, 1, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, kvp.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root1))
			require.Equal(t, merkle.Seqno(1), proof.AddedAtSeqno)
		}

		for _, kvp := range kvps2 {
			ok, _, proof, err := tree.QueryKey(ctx, tr, 1, kvp.Key)
			require.NoError(t, err)
			require.False(t, ok)
			require.NoError(t, verifier.VerifyExclusionProof(ctx, kvp.Key, &proof, root1))
		}

		for _, kvp := range kvps3 {
			ok, _, proof, err := tree.QueryKey(ctx, tr, 1, kvp.Key)
			require.NoError(t, err)
			require.False(t, ok)
			require.NoError(t, verifier.VerifyExclusionProof(ctx, kvp.Key, &proof, root1))
		}

		// STAGE 2
		_, root2, err := tree.Rotate(ctx, tr, nil)
		require.NoError(t, err)

		for _, kvp := range kvps1 {
			ok, ret, proof, err := tree.QueryKey(ctx, tr, 2, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, kvp.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root2))
			require.Equal(t, merkle.Seqno(1), proof.AddedAtSeqno)
		}

		for _, kvp := range kvps2 {
			ok, _, proof, err := tree.QueryKey(ctx, tr, 2, kvp.Key)
			require.NoError(t, err)
			require.False(t, ok)
			require.NoError(t, verifier.VerifyExclusionProof(ctx, kvp.Key, &proof, root2))
		}

		for _, kvp := range kvps3 {
			ok, _, proof, err := tree.QueryKey(ctx, tr, 2, kvp.Key)
			require.NoError(t, err)
			require.False(t, ok)
			require.NoError(t, verifier.VerifyExclusionProof(ctx, kvp.Key, &proof, root2))
		}

		_, root3, err := tree.Build(ctx, tr, kvps2, nil, false)
		require.NoError(t, err)

		for _, kvp := range kvps1 {
			ok, ret, proof, err := tree.QueryKey(ctx, tr, 3, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, kvp.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root3))
			require.Equal(t, merkle.Seqno(1), proof.AddedAtSeqno)
		}

		for _, kvp := range kvps2 {
			ok, ret, proof, err := tree.QueryKey(ctx, tr, 3, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, kvp.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root3))
			require.Equal(t, merkle.Seqno(3), proof.AddedAtSeqno)
		}

		for _, kvp := range kvps3 {
			ok, _, proof, err := tree.QueryKey(ctx, tr, 3, kvp.Key)
			require.NoError(t, err)
			require.False(t, ok)
			require.NoError(t, verifier.VerifyExclusionProof(ctx, kvp.Key, &proof, root3))
		}

		// STAGE 3
		_, _, err = tree.Rotate(ctx, tr, nil)
		require.NoError(t, err)
		_, root5, err := tree.Build(ctx, tr, kvps3, nil, false)
		require.NoError(t, err)

		for _, kvp := range kvps1 {
			ok, ret, proof, err := tree.QueryKey(ctx, tr, 2, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, kvp.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root2))
			require.Equal(t, merkle.Seqno(1), proof.AddedAtSeqno)
		}

		for _, kvp := range kvps1 {
			ok, ret, proof, err := tree.QueryKey(ctx, tr, 5, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, kvp.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root5))
			require.Equal(t, merkle.Seqno(1), proof.AddedAtSeqno)
		}

		for _, kvp := range kvps2 {
			ok, ret, proof, err := tree.QueryKey(ctx, tr, 5, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, kvp.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root5))
			require.Equal(t, merkle.Seqno(3), proof.AddedAtSeqno)
		}

		for _, kvp := range kvps3 {
			ok, ret, proof, err := tree.QueryKey(ctx, tr, 5, kvp.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, kvp.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root5))
			require.Equal(t, merkle.Seqno(5), proof.AddedAtSeqno)
		}
	})

}

func TestLookupHistoricalNode(t *testing.T) {
	cfg, err := newMerkleConfigForTest(merkle.IdentityHasher{}, 1, 1, 1)
	require.NoError(t, err)

	eng := newEngine(cfg)

	k := cfg.GetRootPosition()
	v1 := []byte{1}
	v2 := []byte{2}
	pair1 := merkle.PositionHashPair{Position: *k, Hash: v1}

	pair2 := merkle.PositionHashPair{Position: *k, Hash: v2}

	logctx := NewLoggerContextTodoForTesting(t)
	run(t, eng, func(tr *sqlx.Tx) {
		err := eng.StoreNodes(logctx, tr, 2, 1, []merkle.PositionHashPair{pair1})
		require.NoError(t, err)
		err = eng.StoreNodes(logctx, tr, 3, 1, []merkle.PositionHashPair{pair2})
		require.NoError(t, err)
		v, err := eng.LookupNode(logctx, tr, 3, 1, k)
		require.NoError(t, err)
		require.Equal(t, v2, v)
		v, err = eng.LookupNode(logctx, tr, 2, 1, k)
		require.NoError(t, err)
		require.Equal(t, v1, v)
		v, err = eng.LookupNode(logctx, tr, 1, 1, k)
		require.Error(t, err)
		require.IsType(t, err, merkle.NodeNotFoundError{})
	})
}
