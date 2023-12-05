package merkle

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/mvkdcrypto/mvkd/demo/logger"

	"github.com/stretchr/testify/require"
)

func NewLoggerContextTodoForTesting(t *testing.T) logger.ContextInterface {
	return logger.NewContext(context.TODO(), logger.NewTestLogger(t))
}

func TestZbTreeInsertAtInternal(t *testing.T) {
	cfg, err := newConfigForTest(IdentityHasher{}, 1, 1, 1)
	require.NoError(t, err)

	kvps := []KeyValuePair{
		{Key: []byte{0b00000000}, Value: "alfa"},
		{Key: []byte{0b00010000}, Value: "brav"},
		{Key: []byte{0b00100000}, Value: "char"},
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	i := NewInMemoryStorageEngine(cfg)
	tree, err := NewTree(cfg, defaultStep, i, RootVersionV1)
	require.NoError(t, err)

	s, _, err := tree.Build(logctx, nil, kvps, nil, false)
	require.NoError(t, err)
	require.Equal(t, s, Seqno(1))

	var nodes [][]byte
	for _, node := range i.Nodes[1] {
		nodes = append(nodes, node.p.GetBytes())
	}
}

func TestZbTreeStructureBasic(t *testing.T) {
	batchsize := 1
	cfg, err := newConfigForTest(IdentityHasher{}, 1, batchsize, 1)
	require.NoError(t, err)

	kvps := []KeyValuePair{
		{Key: []byte{0b00000000}, Value: "alfa"},
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	i := NewInMemoryStorageEngine(cfg)
	tree, err := NewTree(cfg, defaultStep, i, RootVersionV1)
	require.NoError(t, err)

	s, hthash, err := tree.Build(logctx, nil, kvps, nil, false)
	require.NoError(t, err)
	require.Equal(t, s, Seqno(1))

	//	tree.Debug(logctx, nil, 1, 1)

	ok, val, _, err := tree.QueryKey(logctx, nil, 1, kvps[0].Key)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, val, "alfa")

	verifier := MerkleProofVerifier{cfg: cfg}
	for _, kvp := range kvps {
		ok, ret, proof, err := tree.QueryKey(logctx, nil, 1, kvp.Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, ret, kvp.Value)
		require.NoError(t, verifier.VerifyInclusionProof(logctx, kvp, &proof, hthash))
	}
}

func TestZbBasic(t *testing.T) {
	batchsize := 1
	cfg, err := newConfigForTest(IdentityHasher{}, 1, batchsize, 1)
	require.NoError(t, err)

	kvps := []KeyValuePair{
		{Key: []byte{0b00000000}, Value: "alfa"},
		{Key: []byte{0b01000000}, Value: "brav"},
		// {Key: []byte{0b00010000}, Value: "char"},
		// {Key: []byte{0b00110000}, Value: "echo"},
		// {Key: []byte{0b00100000}, Value: "foxt"},
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	i := NewInMemoryStorageEngine(cfg)
	tree, err := NewTree(cfg, defaultStep, i, RootVersionV1)
	require.NoError(t, err)

	_, _, err = tree.Build(logctx, nil, kvps, nil, false)
	require.NoError(t, err)

	var nodes [][]byte
	for _, node := range i.Nodes[1] {
		nodes = append(nodes, node.p.GetBytes())
	}
	require.ElementsMatch(t, [][]byte{
		{1}, {2}, {4}, {5}, //{8}, {9}, {16}, {17}, {18}, {19},
	}, nodes)

	p := cfg.GetRootPosition()
	p = cfg.GetChild(p, 0)
	pairs, err := i.LookupPairsUnderPosition(logctx, nil, 1, 1, p)
	require.NoError(t, err)
	var keys [][]byte
	for _, pair := range pairs {
		keys = append(keys, []byte(pair.Key))
	}
	require.Equal(t, [][]byte{[]byte{0}, []byte{0b0100_0000}}, keys)
}

func TestZbTwo(t *testing.T) {
	batchsize := 1
	cfg, err := newConfigForTest(IdentityHasher{}, 1, batchsize, 1)
	require.NoError(t, err)

	// go through iSInternal, and both paths at insertatend
	kvps := []KeyValuePair{
		{Key: []byte{0b00000000}, Value: "alfa"}, // 0x00
		{Key: []byte{0b01000000}, Value: "brav"}, // 0x40
		{Key: []byte{0b00010000}, Value: "char"}, // 0x10
		{Key: []byte{0b00110000}, Value: "echo"}, // 0x30
		// {Key: []byte{0b00100000}, Value: "foxt"}, // 0x20
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	i := NewInMemoryStorageEngine(cfg)
	tree, err := NewTree(cfg, defaultStep, i, RootVersionV1)
	require.NoError(t, err)

	_, _, err = tree.Build(logctx, nil, kvps, nil, false)
	require.NoError(t, err)

	var nodes [][]byte
	for _, node := range i.Nodes[1] {
		nodes = append(nodes, node.p.GetBytes())
	}
	require.ElementsMatch(t, [][]byte{
		{1}, {2}, {5}, {4}, {8}, {16}, {17}, {9},

		// {1}, {2}, {4}, {5}, {8}, {9}, {16}, {17}, {18}, {19},
	}, nodes)
}

func TestZbShape(t *testing.T) {
	batchsize := 1
	cfg, err := newConfigForTest(IdentityHasher{}, 1, batchsize, 1)
	require.NoError(t, err)

	// go through iSInternal, and both paths at insertatend
	kvps := []KeyValuePair{
		{Key: []byte{0b00000000}, Value: "alfa"}, // 0x00
		{Key: []byte{0b01000000}, Value: "brav"}, // 0x40
		{Key: []byte{0b00010000}, Value: "char"}, // 0x10
		{Key: []byte{0b00110000}, Value: "echo"}, // 0x30
		{Key: []byte{0b00100000}, Value: "foxt"}, // 0x20
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	i := NewInMemoryStorageEngine(cfg)
	tree, err := NewTree(cfg, defaultStep, i, RootVersionV1)
	require.NoError(t, err)

	_, _, err = tree.Build(logctx, nil, kvps, nil, false)
	require.NoError(t, err)

	var nodes [][]byte
	for _, node := range i.Nodes[1] {
		nodes = append(nodes, node.p.GetBytes())
	}
	require.ElementsMatch(t, [][]byte{
		{1}, {2}, {4}, {5}, {8}, {9}, {16}, {17}, {18}, {19},
	}, nodes)

	// test minkey max key too
	p := cfg.GetRootPosition()
	p = cfg.GetChild(p, 0)
	p = cfg.GetChild(p, 0)
	p = cfg.GetChild(p, 0)
	allpairs, err := i.LookupAllPairs(logctx, nil, 1, 1)
	var keys [][]byte
	for _, pair := range allpairs {
		keys = append(keys, []byte(pair.Key))
	}
	require.Equal(t, keys, [][]byte{[]byte{0x0}, []byte{0x10}, []byte{0x20}, []byte{0x30}, []byte{0x40}})

	pairs, err := i.LookupPairsUnderPosition(logctx, nil, 1, 1, p)
	require.NoError(t, err)
	keys = nil
	for _, pair := range pairs {
		keys = append(keys, []byte(pair.Key))
	}
	require.Equal(t, keys, [][]byte{[]byte{0}, []byte{0b0001_0000}})
}

// TODO make randomized kvps?
func TestZbExcl(t *testing.T) {
	cfgBin, _, _ := getTreeCfgsWith1_2_3BitsPerIndexUnblinded(t)
	defaultStep := 2
	kvpsBin := []KeyValuePair{
		{Key: []byte{0x00}, Value: "key0x00"},
		{Key: []byte{0x01}, Value: "key0x01"},
		{Key: []byte{0x10}, Value: "key0x10"},
		{Key: []byte{0xfd}, Value: "key0xfd"},
		{Key: []byte{0xfe}, Value: "key0xfe"},
		{Key: []byte{0xff}, Value: "key0xff"},
	}
	kvpsBin2 := []KeyValuePair{
		{Key: []byte{0x05}, Value: "key0x05"},
		{Key: []byte{0x31}, Value: "key0x31"},
		{Key: []byte{0xc1}, Value: "key0xc0"},
		{Key: []byte{0x2d}, Value: "key0x2d"},
		{Key: []byte{0xef}, Value: "key0xef"},
		{Key: []byte{0xfb}, Value: "key0xfb"},
	}
	logctx := NewLoggerContextTodoForTesting(t)

	tests := []struct {
		cfg   Config
		kvps  []KeyValuePair
		kvps2 []KeyValuePair
	}{
		{
			cfg:   cfgBin,
			kvps:  kvpsBin,
			kvps2: kvpsBin2,
		},
	}

	for j, test := range tests {
		if j == 1 {
			continue
		}
		t.Run(fmt.Sprintf("%d-bit arity 1-size-leaf", test.cfg.BitsPerIndex), func(t *testing.T) {
			eng := NewInMemoryStorageEngine(test.cfg)
			tree, err := NewTree(test.cfg, defaultStep, eng, RootVersionV1)
			require.NoError(t, err)

			// building a tree without keys should succeed.
			s, _, err := tree.Build(logctx, nil, nil, nil, false)
			require.NoError(t, err)
			require.EqualValues(t, 1, s)

			p0 := test.kvps[0]
			p1 := test.kvps[1]
			p2 := test.kvps[2]
			p3 := test.kvps[3]
			p4 := test.kvps[4]
			p5 := test.kvps[5]
			verifier := MerkleProofVerifier{cfg: test.cfg}

			// tree.Debug(logctx, nil, 1, 1)

			s, _, err = tree.Build(logctx, nil, []KeyValuePair{p0, p1}, nil, false)
			require.NoError(t, err)
			require.EqualValues(t, 2, s)
			// tree.Debug(logctx, nil, 2, 1)

			s, _, err = tree.Build(logctx, nil, []KeyValuePair{p2}, nil, false)
			require.NoError(t, err)
			require.EqualValues(t, 3, s)

			s, hthash3, err := tree.Build(logctx, nil, []KeyValuePair{p3, p4, p5}, nil, false)
			require.NoError(t, err)
			require.EqualValues(t, 4, s)

			// tree.Debug(logctx, nil, 3, 1)

			for _, kvp := range test.kvps2 {
				ok, _, proof, err := tree.QueryKey(logctx, nil, 4, kvp.Key)
				require.NoError(t, err)
				require.False(t, ok)
				require.NoError(t, verifier.VerifyExclusionProof(logctx, kvp.Key, &proof, hthash3))
			}

		})
	}
}
func TestZbTree(t *testing.T) {
	cfgBin, _, cfgOct := getTreeCfgsWith1_2_3BitsPerIndexUnblinded(t)
	defaultStep := 2
	kvpsBin := []KeyValuePair{
		{Key: []byte{0x00}, Value: "key0x00"},
		{Key: []byte{0x01}, Value: "key0x01"},
		{Key: []byte{0x10}, Value: "key0x10"},
		{Key: []byte{0xfd}, Value: "key0xfd"},
		{Key: []byte{0xfe}, Value: "key0xfe"},
		{Key: []byte{0xff}, Value: "key0xff"},
	}
	kvpsBin2 := []KeyValuePair{
		{Key: []byte{0x05}, Value: "key0x05"},
		{Key: []byte{0x31}, Value: "key0x31"},
		{Key: []byte{0xc0}, Value: "key0xc0"},
		{Key: []byte{0x2d}, Value: "key0x2d"},
		{Key: []byte{0xef}, Value: "key0xef"},
		{Key: []byte{0xfb}, Value: "key0xfb"},
	}
	kvpsOct := []KeyValuePair{
		{Key: []byte{0x00, 0x00, 0x00}, Value: "key0x000000"},
		{Key: []byte{0x00, 0x00, 0x01}, Value: "key0x000001"},
		{Key: []byte{0x00, 0x10, 0x00}, Value: "key0x001000"},
		{Key: []byte{0xff, 0xff, 0xfd}, Value: "key0xfffffd"},
		{Key: []byte{0xff, 0xff, 0xfe}, Value: "key0xfffffe"},
		{Key: []byte{0xff, 0xff, 0xff}, Value: "key0xffffff"},
	}
	kvpsOct2 := []KeyValuePair{
		{Key: []byte{0x01, 0x00, 0x00}, Value: "key0x010000"},
		{Key: []byte{0x00, 0x01, 0x01}, Value: "key0x000101"},
		{Key: []byte{0x00, 0x11, 0x00}, Value: "key0x001100"},
		{Key: []byte{0xff, 0xfe, 0xfd}, Value: "key0xfffefd"},
		{Key: []byte{0xff, 0xff, 0xfa}, Value: "key0xfffffa"},
		{Key: []byte{0xfc, 0xff, 0xff}, Value: "key0xfcffff"},
	}
	logctx := NewLoggerContextTodoForTesting(t)

	tests := []struct {
		cfg   Config
		kvps  []KeyValuePair
		kvps2 []KeyValuePair
	}{
		{
			cfg:   cfgBin,
			kvps:  kvpsBin,
			kvps2: kvpsBin2,
		},
		{
			cfg:   cfgOct,
			kvps:  kvpsOct,
			kvps2: kvpsOct2,
		},
	}

	for j, test := range tests {
		if j == 1 {
			continue
		}
		t.Run(fmt.Sprintf("%d-bit arity 1-size-leaf", test.cfg.BitsPerIndex), func(t *testing.T) {
			eng := NewInMemoryStorageEngine(test.cfg)
			tree, err := NewTree(test.cfg, defaultStep, eng, RootVersionV1)
			require.NoError(t, err)

			seq, md, td, err := tree.GetLatestRoot(logctx, nil)
			require.Error(t, err)
			require.IsType(t, NoLatestRootFoundError{}, err)
			require.Equal(t, Seqno(0), seq, "Tree should have Seqno 0 as no insertions were made, got %v instead", seq)
			require.Nil(t, md.BareRootHash, "Tree root should not have a bareRootHash as no insertions were made")
			require.Nil(t, td, "Tree root should not have a root hash as no insertions were made")

			for _, kvp := range test.kvps {
				_, _, _, err = tree.QueryKey(logctx, nil, 0, kvp.Key)
				require.Error(t, err)
				require.IsType(t, InvalidSeqnoError{}, err, "Expected InvalidSeqnoError, but got %v", err)
				_, _, _, err = tree.QueryKey(logctx, nil, 7, kvp.Key)
				require.Error(t, err)
				require.IsType(t, InvalidSeqnoError{}, err, "Expected InvalidSeqnoError, but got %v", err)
			}

			// building a tree without keys should succeed.
			s, _, err := tree.Build(logctx, nil, nil, nil, false)
			require.NoError(t, err)
			require.EqualValues(t, 1, s)

			p0 := test.kvps[0]
			p1 := test.kvps[1]
			p2 := test.kvps[2]
			p3 := test.kvps[3]
			p4 := test.kvps[4]
			p5 := test.kvps[5]
			verifier := MerkleProofVerifier{cfg: test.cfg}

			s, hthash1, err := tree.Build(logctx, nil, []KeyValuePair{p0, p1}, nil, false)
			require.NoError(t, err)
			require.EqualValues(t, 2, s)

			ok, _, _, err := tree.QueryKey(logctx, nil, 1, p0.Key)
			require.NoError(t, err)
			require.False(t, ok)

			ok, ret, proof, err := tree.QueryKey(logctx, nil, 2, p0.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, p0.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(logctx, p0, &proof, hthash1))

			ok, ret, proof, err = tree.QueryKey(logctx, nil, 2, p1.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, p1.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(logctx, p1, &proof, hthash1))

			s, hthash2, err := tree.Build(logctx, nil, []KeyValuePair{p2, p3, p4}, nil, false)
			require.NoError(t, err)
			require.EqualValues(t, 3, s)

			s, hthash3, err := tree.Build(logctx, nil, []KeyValuePair{p5}, nil, false)
			require.NoError(t, err)
			require.EqualValues(t, 4, s)

			ok, ret, proof, err = tree.QueryKey(logctx, nil, 2, p1.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, p1.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(logctx, p1, &proof, hthash1))

			ok, ret, proof, err = tree.QueryKey(logctx, nil, 4, p1.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, p1.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(logctx, p1, &proof, hthash3))

			ok, ret, proof, err = tree.QueryKey(logctx, nil, 3, p4.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, p4.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(logctx, p4, &proof, hthash2))

			ok, ret, proof, err = tree.QueryKey(logctx, nil, 4, p5.Key)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, p5.Value, ret)
			require.NoError(t, verifier.VerifyInclusionProof(logctx, p5, &proof, hthash3))

			for _, kvp := range test.kvps2 {
				ok, _, proof, err := tree.QueryKey(logctx, nil, 4, kvp.Key)
				require.NoError(t, err)
				require.False(t, ok)
				require.NoError(t, verifier.VerifyExclusionProof(logctx, kvp.Key, &proof, hthash3))
			}

		})
	}
}

func TestConsistencyProof(t *testing.T) {
	require.EqualValues(t, []int{17, 21, 27, 7, 35}, consistencyProofIndices(10, 19))
	require.EqualValues(t, []int{4, 6, 1, 11}, consistencyProofIndices(3, 8))
	require.EqualValues(t, []int{11}, consistencyProofIndices(4, 8))
	require.EqualValues(t, []int{8, 10, 13, 3}, consistencyProofIndices(5, 8))
}

func TestExtensionProofsHappy(t *testing.T) {
	cfg, err := newConfigForTest(SHA512_256Encoder{}, 1, 1, 3)
	require.NoError(t, err)

	// make test deterministic
	rand.Seed(1)

	tree, err := NewTree(cfg, 2, NewInMemoryStorageEngine(cfg), RootVersionV1)
	require.NoError(t, err)

	htrootHashes := make(map[Seqno][]byte)

	maxSeqno := Seqno(5) // 100

	keys, _, err := MakeRandomKeysForTesting(uint(cfg.KeysByteLength), int(maxSeqno), 0)
	require.NoError(t, err)
	kvps, err := MakeRandomKVPFromKeysForTesting(keys)

	// build a bunch of tree versions:
	for j := Seqno(1); j <= maxSeqno; j++ {
		addOnsHash := []byte(nil)
		// put a random AddOnsHash in half of the tree roots
		if rand.Intn(2) == 1 {
			buf := make([]byte, 32)
			rand.Read(buf)
			addOnsHash = []byte(buf)
		}
		require.NoError(t, err)
		kvp := []KeyValuePair{kvps[int(j)-1]}
		_, hthash, err := tree.Build(NewLoggerContextTodoForTesting(t), nil, kvp, addOnsHash, false)
		htrootHashes[j] = hthash
		require.NoError(t, err)
	}

	verifier := NewMerkleProofVerifier(cfg)

	numTests := 50
	for j := 0; j < numTests; j++ {
		//startSeqno := Seqno(rand.Intn(int(maxSeqno)-1) + 1)
		//endSeqno := Seqno(rand.Intn(int(maxSeqno)-1) + 1)
		startSeqno := maxSeqno
		endSeqno := maxSeqno

		if startSeqno > endSeqno {
			startSeqno, endSeqno = endSeqno, startSeqno
		}

		eProof, err := tree.GetExtensionProof(NewLoggerContextTodoForTesting(t), nil, startSeqno, endSeqno)
		require.NoError(t, err)

		err = verifier.VerifyExtensionProof(NewLoggerContextTodoForTesting(t), &eProof, startSeqno, htrootHashes[startSeqno], endSeqno, htrootHashes[endSeqno])
		require.NoError(t, err)
	}

	// Test the special cases start == end and start == end - 1
	startSeqno := Seqno(rand.Intn(int(maxSeqno)-1) + 1)
	endSeqno := startSeqno

	eProof, err := tree.GetExtensionProof(NewLoggerContextTodoForTesting(t), nil, startSeqno, endSeqno)
	require.NoError(t, err)

	err = verifier.VerifyExtensionProof(NewLoggerContextTodoForTesting(t), &eProof, startSeqno, htrootHashes[startSeqno], endSeqno, htrootHashes[endSeqno])
	require.NoError(t, err)

	endSeqno = startSeqno + 1

	eProof, err = tree.GetExtensionProof(NewLoggerContextTodoForTesting(t), nil, startSeqno, endSeqno)
	require.NoError(t, err)

	err = verifier.VerifyExtensionProof(NewLoggerContextTodoForTesting(t), &eProof, startSeqno, htrootHashes[startSeqno], endSeqno, htrootHashes[endSeqno])
	require.NoError(t, err)

}

func TestZbTreeStructureLongKeys(t *testing.T) {
	cfg, err := newConfigForTest(IdentityHasher{}, 1, 1, 32)
	require.NoError(t, err)

	kvps := []KeyValuePair{
		{Key: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Value: "alfa"},
		{Key: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Value: "beta"},
		//{Key: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		//	0, 0, 0, 0, 0, 0, 0, 0, 232, 0, 0, 0, 0, 0, 0, 0}, Value: "gamma"},
	}
	defaultStep := 2
	logctx := NewLoggerContextTodoForTesting(t)

	i := NewInMemoryStorageEngine(cfg)
	tree, err := NewTree(cfg, defaultStep, i, RootVersionV1)
	require.NoError(t, err)

	s, hthash, err := tree.Build(logctx, nil, kvps, nil, false)
	require.NoError(t, err)
	require.Equal(t, s, Seqno(1))

	ok, val, _, err := tree.QueryKey(logctx, nil, 1, kvps[0].Key)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, val, "alfa")

	verifier := MerkleProofVerifier{cfg: cfg}
	for _, kvp := range kvps {
		ok, ret, proof, err := tree.QueryKey(logctx, nil, 1, kvp.Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, ret, kvp.Value)
		require.NoError(t, verifier.VerifyInclusionProof(logctx, kvp, &proof, hthash))
	}
}

// Test historical proofs
func TestHonestMerkleProofsVerifySuccesfullyLargeTree(t *testing.T) {
	cfg1, err := newConfigForTest(IdentityHasher{}, 1, 1, 32)
	require.NoError(t, err)

	cfg2, err := newConfigForTestWithVRF(SHA512_256Encoder{}, 1, 1)
	require.NoError(t, err)

	// Make test deterministic.
	rand.Seed(1)

	tests := []struct {
		cfg         Config
		step        int
		numIncPairs int
		numExcPairs int
		rootVersion RootVersion
		vrf         bool
	}{
		{cfg1, 1, 200, 20, RootVersionV1, false},
		{cfg2, 1, 200, 20, RootVersionV1, true},
	}

	ctx := NewLoggerContextTodoForTesting(t)

	for _, test := range tests {
		t.Run(fmt.Sprintf("%v bits %v values per leaf tree; vrf on: %t", test.cfg.BitsPerIndex, test.cfg.MaxValuesPerLeaf, test.vrf), func(t *testing.T) {
			tree, err := NewTree(test.cfg, test.step, NewInMemoryStorageEngine(test.cfg), test.rootVersion)
			require.NoError(t, err)
			verifier := MerkleProofVerifier{cfg: test.cfg}

			keys, keysNotInTree, err := MakeRandomKeysForTesting(uint(test.cfg.KeysByteLength), test.numIncPairs, test.numExcPairs)
			require.NoError(t, err)
			keys2, _, err := MakeRandomKeysForTesting(uint(test.cfg.KeysByteLength), test.numIncPairs, test.numExcPairs)
			require.NoError(t, err)

			kvp1, err := MakeRandomKVPFromKeysForTesting(keys)
			require.NoError(t, err)
			kvp2, err := MakeRandomKVPFromKeysForTesting(keys2)
			require.NoError(t, err)

			s1, rootHash1, err := tree.Build(ctx, nil, kvp1, nil, false)
			require.NoError(t, err)
			require.EqualValues(t, 1, s1)

			for i, key := range keys {
				ok, kvpRet, proof, err := tree.QueryKey(ctx, nil, 1, key)
				require.NoError(t, err)
				require.True(t, ok)
				require.Equal(t, kvp1[i].Value, kvpRet)
				err = verifier.VerifyInclusionProof(ctx, kvp1[i], &proof, rootHash1)
				require.NoErrorf(t, err, "Error verifying proof for key %v: %v", key, err)
			}
			for _, key := range keysNotInTree {
				ok, _, proof, err := tree.QueryKey(ctx, nil, 1, key)
				require.NoError(t, err)
				require.False(t, ok)
				require.NoError(t, verifier.VerifyExclusionProof(ctx, key, &proof, rootHash1))
			}

			s2, rootHash2, err := tree.Build(ctx, nil, kvp2, nil, false)
			require.NoError(t, err)
			require.EqualValues(t, 2, s2)

			for i, key := range keys2 {
				ok, kvpRet, proof, err := tree.QueryKey(ctx, nil, 2, key)
				require.NoError(t, err)
				require.True(t, ok)
				require.Equal(t, kvp2[i].Value, kvpRet)
				require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp2[i], &proof, rootHash2))
			}
			for i, key := range keys {
				ok, kvpRet, proof, err := tree.QueryKey(ctx, nil, 2, key)
				require.NoError(t, err)
				require.True(t, ok)
				require.Equal(t, kvp1[i].Value, kvpRet)
				require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp1[i], &proof, rootHash2))

				ok, kvpRet, proof, err = tree.QueryKey(ctx, nil, 1, key)
				require.NoError(t, err)
				require.True(t, ok)
				require.Equal(t, kvp1[i].Value, kvpRet)
				require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp1[i], &proof, rootHash1))
			}

			for _, key := range keysNotInTree {
				ok, _, proof, err := tree.QueryKey(ctx, nil, 2, key)
				require.NoError(t, err)
				require.False(t, ok)
				require.NoError(t, verifier.VerifyExclusionProof(ctx, key, &proof, rootHash2))

				ok, _, proof, err = tree.QueryKey(ctx, nil, 1, key)
				require.NoError(t, err)
				require.False(t, ok)
				require.NoError(t, verifier.VerifyExclusionProof(ctx, key, &proof, rootHash1))
			}

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
	cfg, err := newConfigForTestWithVRF(SHA512_256Encoder{}, 1, 1)
	require.NoError(t, err)

	kvps1 := []KeyValuePair{
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000000000"), Value: "alfa"},
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000000010"), Value: "brav"},
	}
	kvps2 := []KeyValuePair{
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000000100"), Value: "char"},
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000001000"), Value: "delt"},
	}
	kvps3 := []KeyValuePair{
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000010000"), Value: "echo"},
		{Key: hexDecode("0000000000000000000000000000000000000000000000000000000000100000"), Value: "foxt"},
	}
	defaultStep := 2
	ctx := NewLoggerContextTodoForTesting(t)

	i := NewInMemoryStorageEngine(cfg)
	tree, err := NewTree(cfg, defaultStep, i, RootVersionV1)
	require.NoError(t, err)
	verifier := MerkleProofVerifier{cfg: cfg}

	// STAGE 1
	_, root1, err := tree.Build(ctx, nil, kvps1, nil, false)
	require.NoError(t, err)

	for _, kvp := range kvps1 {
		ok, ret, proof, err := tree.QueryKey(ctx, nil, 1, kvp.Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, kvp.Value, ret)
		require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root1))
		require.Equal(t, Seqno(1), proof.AddedAtSeqno)
	}

	for _, kvp := range kvps2 {
		ok, _, proof, err := tree.QueryKey(ctx, nil, 1, kvp.Key)
		require.NoError(t, err)
		require.False(t, ok)
		require.NoError(t, verifier.VerifyExclusionProof(ctx, kvp.Key, &proof, root1))
	}

	for _, kvp := range kvps3 {
		ok, _, proof, err := tree.QueryKey(ctx, nil, 1, kvp.Key)
		require.NoError(t, err)
		require.False(t, ok)
		require.NoError(t, verifier.VerifyExclusionProof(ctx, kvp.Key, &proof, root1))
	}

	// STAGE 2
	_, root2, err := tree.Rotate(ctx, nil, nil)
	require.NoError(t, err)

	for _, kvp := range kvps1 {
		ok, ret, proof, err := tree.QueryKey(ctx, nil, 2, kvp.Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, kvp.Value, ret)
		require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root2))
		require.Equal(t, Seqno(1), proof.AddedAtSeqno)
	}

	for _, kvp := range kvps2 {
		ok, _, proof, err := tree.QueryKey(ctx, nil, 2, kvp.Key)
		require.NoError(t, err)
		require.False(t, ok)
		require.NoError(t, verifier.VerifyExclusionProof(ctx, kvp.Key, &proof, root2))
	}

	for _, kvp := range kvps3 {
		ok, _, proof, err := tree.QueryKey(ctx, nil, 2, kvp.Key)
		require.NoError(t, err)
		require.False(t, ok)
		require.NoError(t, verifier.VerifyExclusionProof(ctx, kvp.Key, &proof, root2))
	}

	_, root3, err := tree.Build(ctx, nil, kvps2, nil, false)
	require.NoError(t, err)

	for _, kvp := range kvps1 {
		ok, ret, proof, err := tree.QueryKey(ctx, nil, 3, kvp.Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, kvp.Value, ret)
		require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root3))
		require.Equal(t, Seqno(1), proof.AddedAtSeqno)
	}

	for _, kvp := range kvps2 {
		ok, ret, proof, err := tree.QueryKey(ctx, nil, 3, kvp.Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, kvp.Value, ret)
		require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root3))
		require.Equal(t, Seqno(3), proof.AddedAtSeqno)
	}

	for _, kvp := range kvps3 {
		ok, _, proof, err := tree.QueryKey(ctx, nil, 3, kvp.Key)
		require.NoError(t, err)
		require.False(t, ok)
		require.NoError(t, verifier.VerifyExclusionProof(ctx, kvp.Key, &proof, root3))
	}

	// STAGE 3
	_, _, err = tree.Rotate(ctx, nil, nil)
	require.NoError(t, err)
	_, root5, err := tree.Build(ctx, nil, kvps3, nil, false)
	require.NoError(t, err)

	for _, kvp := range kvps1 {
		ok, ret, proof, err := tree.QueryKey(ctx, nil, 2, kvp.Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, kvp.Value, ret)
		require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root2))
		require.Equal(t, Seqno(1), proof.AddedAtSeqno)
	}

	for _, kvp := range kvps1 {
		ok, ret, proof, err := tree.QueryKey(ctx, nil, 5, kvp.Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, kvp.Value, ret)
		require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root5))
		require.Equal(t, Seqno(1), proof.AddedAtSeqno)
	}

	for _, kvp := range kvps2 {
		ok, ret, proof, err := tree.QueryKey(ctx, nil, 5, kvp.Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, kvp.Value, ret)
		require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root5))
		require.Equal(t, Seqno(3), proof.AddedAtSeqno)
	}

	for _, kvp := range kvps3 {
		ok, ret, proof, err := tree.QueryKey(ctx, nil, 5, kvp.Key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, kvp.Value, ret)
		require.NoError(t, verifier.VerifyInclusionProof(ctx, kvp, &proof, root5))
		require.Equal(t, Seqno(5), proof.AddedAtSeqno)
	}
}
