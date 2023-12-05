package merkle

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/keybase/go-codec/codec"
	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/vrf"
	"github.com/pkg/errors"
)

// Tree is the MerkleTree class; it needs an engine and a configuration
// to run
type Tree struct {
	sync.RWMutex

	cfg Config
	eng StorageEngine

	newRootVersion RootVersion

	historyTree *LBBMT

	// step is an optimization parameter for Querykey that
	// controls how many path positions at a time the tree requests from the
	// storage engine. Lower values result in more storage engine requests, but
	// less of the (somewhat expensive) bit fiddling operations.  Values higher
	// than 63 are not recommended as the bit operations (in the best case)
	// cannot be done using a single 64 bit word and become more expensive. This
	// is unnecessary if the tree has random keys (as such a tree should be
	// approximately balanced and have short-ish paths).
	step int

	rotateNewProofs   map[string][]byte
	fastpathN         int
	FastpathFallbacks int

	fastpathMiss bool

	// these fields are used as buffers during tree building to avoid making
	// many short lived memory allocations
	bufLeaf           Node
	htrPathBuf        []ChildIndex
	pathBuf           []ChildIndex
	Rehashc           int
	Depths            []int
	sibpos            []Position
	tostore           []PositionHashPair
	nodebuf           *Node
	insertPairPathBuf []ChildIndex
	posBuf            []*Position

	LastHideEl time.Duration

	LastRotateVRFEl   time.Duration
	LastRotateBuildEl time.Duration
}

// NewTree makes a new tree
func NewTree(c Config, step int, e StorageEngine, v RootVersion) (*Tree, error) {
	if step < 1 {
		return nil, fmt.Errorf("step must be a positive integer")
	}

	historyTree := NewLBBMT(e)
	return &Tree{cfg: c, eng: e, step: step,
		newRootVersion: v, historyTree: historyTree,
		rotateNewProofs: make(map[string][]byte), fastpathN: 10}, nil
}

func (t *Tree) Eng() StorageEngine {
	return t.eng
}

type TransparencyDigest []byte

// Equal compares two keys byte by byte
func (d TransparencyDigest) Equal(d2 TransparencyDigest) bool {
	return bytes.Equal(d, d2)
}

// Key is a byte-array, and it is the type of the keys in the KeyValuePairs that
// the tree can store.
type Key []byte

func (k Key) String() string {
	return hex.EncodeToString(k)
}

// Equal compares two keys byte by byte
func (k Key) Equal(k2 Key) bool {
	return bytes.Equal(k, k2)
}

// Cmp compares two keys lexicographically as byte slices
func (k Key) Cmp(k2 Key) int {
	return bytes.Compare(k, k2)
}

// HiddenKey is the image of a Key under a VRF
type HiddenKey []byte

// HiddenValue is the image of a Value under a commitment scheme
type HiddenValue []byte

// Equal compares two keys byte by byte
func (k HiddenKey) Equal(k2 HiddenKey) bool {
	return bytes.Equal(k, k2)
}

func (k HiddenKey) Cmp(k2 HiddenKey) int {
	return bytes.Compare(k, k2)
}

type EncodedValue []byte

type Entropy []byte

type HiddenKeyValuePair struct {
	Key          Key          `db:"key"`
	AddedAtSeqno Seqno        `db:"added_at_seqno"` // doesn't bump on rotations
	HiddenKey    HiddenKey    `db:"hidden_key"`
	EncodedValue EncodedValue `db:"encoded_value"`
	Entropy      Entropy      `db:"entropy"`
}

// Seqno is an integer used to differentiate different versions of a merkle tree.
type Seqno int64

// Period increments with the VRF key rotates.
type Period int64

type SeqnoSortedAsInt []Seqno

func (d SeqnoSortedAsInt) Len() int {
	return len(d)
}

func (d SeqnoSortedAsInt) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func (d SeqnoSortedAsInt) Less(i, j int) bool {
	return d[i] < d[j]
}

// ChildIndex specifies one of an iNode's child nodes.
type ChildIndex int

// KeyValuePair is something the merkle tree can store. The key can be something
// like a UID or a TLF ID.  The Value is a generic interface, so you can store
// anything there, as long as it obeys Msgpack-decoding behavior. The Value must
// be of the same type returned by ValueConstructor in the TreeConfig, otherwise
// the behavior is undefined.
type KeyValuePair struct {
	_struct struct{}    `codec:",toarray"` //nolint
	Key     Key         `codec:"k"`
	Value   interface{} `codec:"v"`
}

type KeyHashPair struct {
	_struct      struct{}  `codec:",toarray"` //nolint
	HiddenKey    HiddenKey `codec:"k"`
	Hash         []byte    `codec:"h"`
	AddedAtSeqno Seqno     `codec:"h"` // checked by auditors
}

// NodeType is used to distinguish serialized internal nodes from leaves in the tree
type NodeType uint8

const (
	NodeTypeNone  NodeType = 0
	NodeTypeINode NodeType = 1
	NodeTypeLeaf  NodeType = 2
)

// A Node is either an internal node or a leaf: INodes and LeafHashes cannot
// both have length > 0 (else msgpack encoding will fail). This struct
// is only used for hashing and is not stored.
type Node struct {
	INodes     [][]byte
	LeafHashes []KeyHashPair
}

func (n *Node) HashLeafHashes() []byte {
	h := sha256.New()
	h.Write([]byte("\x01")) // domain separation for inode
	seqnob := make([]byte, 4)
	for _, lh := range n.LeafHashes {
		h.Write(lh.HiddenKey) // require constant length for collision resistance
		h.Write(lh.Hash)      // require constant length for collision resistance
		binary.BigEndian.PutUint32(seqnob, uint32(lh.AddedAtSeqno))
		h.Write(seqnob) // require constant length for collision resistance
	}
	return h.Sum(nil)
}

func (n *Node) HashINodes() []byte {
	h := sha256.New()
	h.Write([]byte("\x00")) // domain separation for inode
	for _, inode := range n.INodes {
		h.Write(inode) // require constant length for collision resistance
	}
	return h.Sum(nil)
}

var _ codec.Selfer = &Node{}

func (n *Node) CodecEncodeSelf(e *codec.Encoder) {
	if n.INodes != nil && n.LeafHashes != nil && len(n.INodes) > 0 && len(n.LeafHashes) > 0 {
		panic("Cannot Encode a node with both Inodes and LeafHashes")
	}

	if n.INodes != nil && len(n.INodes) > 0 {
		e.MustEncode(NodeTypeINode)
		e.MustEncode(n.INodes)
		return
	}

	// Note: we encode empty nodes (with empty or nil LeafHashes) as leaf nodes.
	// This is so we can represent a tree with no values as a single (empty)
	// leaf node.
	e.MustEncode(NodeTypeLeaf)
	// encode empty slices and nil slices equally
	if len(n.LeafHashes) == 0 {
		e.MustEncode([]KeyHashPair(nil))
	} else {
		e.MustEncode(n.LeafHashes)
	}
}

func (n *Node) CodecDecodeSelf(d *codec.Decoder) {
	var nodeType NodeType
	d.MustDecode(&nodeType)
	switch nodeType {
	case NodeTypeINode:
		d.MustDecode(&n.INodes)
	case NodeTypeLeaf:
		d.MustDecode(&n.LeafHashes)
	default:
		panic("Unrecognized NodeType")
	}
}

type PositionHashPair struct {
	_struct  struct{} `codec:",toarray"` //nolint
	Position Position `codec:"p" db:"position"`
	Hash     []byte   `codec:"h" db:"hash"`
}

type RootVersion uint8

const (
	RootVersionV1      RootVersion = 1
	CurrentRootVersion RootVersion = RootVersionV1
)

type RootMetadata struct {
	_struct      struct{} `codec:",toarray"` //nolint
	RootVersion  RootVersion
	Seqno        Seqno
	BareRootHash []byte

	Period Period

	VRFPublicKeyX []byte
	VRFPublicKeyY []byte

	//  AddOnsHash is the (currently empty) hash of a (not yet defined) data
	//  structure which will contain a map[string]Hash (or even
	//  map[string]interface{}) which can contain arbitrary values. This AddOn
	//  struct is not used in verifying proofs, and new elements can be added to
	//  this map without bumping the RootVersion. Clients are expected to ignore
	//  fields in this map which they do not understand.
	AddOnsHash []byte
}

func RandomBytes(n int) ([]byte, error) {
	ret := make([]byte, n)
	_, err := rand.Read(ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (t *Tree) makeRootMetadata(ctx logger.ContextInterface, tr Transaction, seqno Seqno,
	period Period, newRootHash []byte, vrfPublicKey *vrf.PublicKey, addOnsHash []byte) (RootMetadata, error) {
	root := RootMetadata{
		Seqno:         seqno,
		RootVersion:   t.newRootVersion,
		BareRootHash:  newRootHash,
		Period:        period,
		VRFPublicKeyX: vrfPublicKey.X.Bytes(),
		VRFPublicKeyY: vrfPublicKey.Y.Bytes(),
		AddOnsHash:    addOnsHash,
	}

	return root, nil
}

func (t *Tree) hideKVPairs(ctx logger.ContextInterface, tr Transaction, per Period, sk *vrf.PrivateKey, kvps []KeyValuePair, seqnos []Seqno, fake bool) ([]HiddenKeyValuePair, [][]byte, error) {
	var kevps []HiddenKeyValuePair
	var vrfProofs [][]byte
	var err error
	st := time.Now()
	if !fake && len(kvps) >= 100 {
		kevps, vrfProofs, err = t.hideKVPairsPar(sk, kvps, seqnos, fake)
		if err != nil {
			return nil, nil, err
		}
	} else {
		kevps, vrfProofs, err = t.hideKVPairsSeq(sk, kvps, seqnos, fake)
		if err != nil {
			return nil, nil, err
		}
	}
	t.LastHideEl = time.Since(st)

	f := func() {
		var newKeys []Key
		var newHiddenKeys []HiddenKey
		for _, kevp := range kevps {
			newKeys = append(newKeys, kevp.Key)
			newHiddenKeys = append(newHiddenKeys, kevp.HiddenKey)
		}
		err = t.eng.StoreVRFCache(ctx, tr, per, newKeys, newHiddenKeys, vrfProofs)
		if err != nil {
			fmt.Printf("Failed to store vrf: %s\n", err)
		}
	}
	f()
	// _, ok := t.eng.(*InMemoryStorageEngine)
	// if ok {
	// 	f()
	// } else {
	// 	go f()
	// }

	return kevps, vrfProofs, nil
}

func (t *Tree) hideKVPairsPar(sk *vrf.PrivateKey, kvps []KeyValuePair, seqnos []Seqno, fake bool) ([]HiddenKeyValuePair, [][]byte, error) {
	hkvps := make([]HiddenKeyValuePair, len(kvps))
	prfs := make([][]byte, len(kvps))
	var wg sync.WaitGroup
	for idx, kvp := range kvps {
		wg.Add(1)
		idx := idx
		kvp := kvp
		encodedValue, err := t.cfg.Encoder.Encode(kvp.Value)
		if err != nil {
			return nil, nil, err
		}
		entropy, err := RandomBytes(32)
		if err != nil {
			return nil, nil, err
		}
		go func() {
			defer wg.Done()
			hk, prf, err := t.hideKey(sk, kvp.Key, fake)
			if err != nil {
				panic(err)
			}
			hkvp := HiddenKeyValuePair{
				Key:          kvp.Key,
				HiddenKey:    hk,
				EncodedValue: encodedValue,
				Entropy:      entropy,
				AddedAtSeqno: seqnos[idx],
			}
			hkvps[idx] = hkvp
			prfs[idx] = prf
		}()
	}
	wg.Wait()
	return hkvps, prfs, nil
}

func (t *Tree) hideKVPairsSeq(sk *vrf.PrivateKey, kvps []KeyValuePair, seqnos []Seqno, fake bool) ([]HiddenKeyValuePair, [][]byte, error) {
	hkvps := make([]HiddenKeyValuePair, len(kvps))
	prfs := make([][]byte, len(kvps))
	for idx, kvp := range kvps {
		encodedValue, err := t.cfg.Encoder.Encode(kvp.Value)
		if err != nil {
			return nil, nil, err
		}
		entropy, err := RandomBytes(32)
		if err != nil {
			return nil, nil, err
		}
		hk, prf, err := t.hideKey(sk, kvp.Key, fake)
		if err != nil {
			return nil, nil, err
		}
		hkvp := HiddenKeyValuePair{
			Key:          kvp.Key,
			HiddenKey:    hk,
			EncodedValue: encodedValue,
			Entropy:      entropy,
			AddedAtSeqno: seqnos[idx],
		}
		hkvps[idx] = hkvp
		prfs[idx] = prf
	}
	return hkvps, prfs, nil
}

func (t *Tree) hideKey(sk *vrf.PrivateKey, k Key, fake bool) (hk HiddenKey, proof []byte, err error) {
	if len(t.rotateNewProofs) > 0 {
		proof := t.rotateNewProofs[k.String()]
		hiddenKey, err := t.cfg.ECVRF.ProofToHash(proof)
		if err != nil {
			return nil, nil, errors.Wrap(err, "hide key rotate fastpath")

		}
		return hiddenKey, proof, nil
	}

	var hiddenKey HiddenKey
	var vrfProof []byte
	if fake {
		hasher := sha256.New()
		hasher.Write(k)
		hiddenKey = hasher.Sum(nil)
		vrfProof = []byte("fake")
	} else {
		vrfProof = t.cfg.ECVRF.Prove(sk, k)
		hiddenKey, err = t.cfg.ECVRF.ProofToHash(vrfProof)
		if err != nil {
			return nil, nil, err
		}
	}
	return hiddenKey, vrfProof, nil
}

func sortHiddenKeyValuePairsInPlace(hkvps []HiddenKeyValuePair) {
	sort.Slice(hkvps, func(i, j int) bool {
		a := hkvps[i]
		b := hkvps[j]
		return a.HiddenKey.Cmp(b.HiddenKey) <= 0
	})
}

func (t *Tree) newVRFPrivateKey() (*vrf.PrivateKey, error) {
	skBytes, err := RandomBytes(32)
	if err != nil {
		return nil, err
	}
	k := vrf.NewKey(t.cfg.ECVRF.Params().EC(), skBytes)
	return k, nil
}

func (t *Tree) lookupCurrentEpoch(ctx logger.ContextInterface, tr Transaction) (Seqno, Period, *vrf.PrivateKey, error) {
	rootMd, err := t.eng.LookupLatestRoot(ctx, tr)
	switch err.(type) {
	case nil:
		period := rootMd.Period
		sk, err := t.eng.LookupVRFPrivateKey(ctx, tr, period)
		if err != nil {
			return 0, 0, nil, err
		}
		return rootMd.Seqno, period, sk, nil
	case NoLatestRootFoundError:
		return 0, 0, nil, nil
	default:
		return 0, 0, nil, err
	}
}

// Build builds a new tree version, taking a batch input.
// NOTE: This function is modified from the original code which required each successive
// sortedKVPairs's keys to be a superset of the previous. There is no such requirement now.
// Modifying values is supported as well, though might not be used in practice.
func (t *Tree) Build(ctx logger.ContextInterface, tr Transaction,
	kvPairs []KeyValuePair, addOnsHash []byte, fake bool) (s Seqno, td TransparencyDigest, err error) {
	t.Lock()
	defer t.Unlock()

	oldSeqno, oldPeriod, oldSk, err := t.lookupCurrentEpoch(ctx, tr)
	if err != nil {
		return 0, nil, err
	}

	seqno := oldSeqno + 1
	period := oldPeriod
	sk := oldSk

	if oldSeqno == 0 {
		period = 1

		sk, err = t.newVRFPrivateKey()
		if err != nil {
			return 0, nil, err
		}
		err = t.eng.StoreVRFPrivateKey(ctx, tr, period, sk)
		if err != nil {
			return 0, nil, err
		}
	}

	var seqnos []Seqno
	for _ = range kvPairs {
		seqnos = append(seqnos, seqno)
	}

	td, err = t.finalizeEpoch(ctx, tr, seqno, period, sk, kvPairs, seqnos, addOnsHash, fake)
	if err != nil {
		return 0, nil, err
	}

	return seqno, td, nil
}

func (t *Tree) Rotate(ctx logger.ContextInterface, tr Transaction, addOnsHash []byte) (s Seqno, td TransparencyDigest, err error) {
	t.Lock()
	defer t.Unlock()

	oldSeqno, oldPeriod, oldSk, err := t.lookupCurrentEpoch(ctx, tr)
	if err != nil {
		return 0, nil, err
	}

	if oldSeqno == 0 {
		return 0, nil, fmt.Errorf("cannot rotate on epoch 1")
	}

	seqno := oldSeqno + 1
	period := oldPeriod + 1

	oldHKVPairs, err := t.eng.LookupAllPairs(ctx, tr, oldSeqno, oldPeriod)
	if err != nil {
		return 0, nil, err
	}
	var kvPairs []KeyValuePair
	var keys [][]byte
	var seqnos []Seqno
	var oldProofs [][]byte
	for _, hkvPair := range oldHKVPairs {
		valContainer := t.cfg.ConstructValueContainer()
		err = t.cfg.Encoder.Decode(&valContainer, hkvPair.EncodedValue)
		if err != nil {
			return 0, nil, err
		}
		kvPairs = append(kvPairs, KeyValuePair{Key: hkvPair.Key, Value: valContainer})
		keys = append(keys, []byte(hkvPair.Key))
		seqnos = append(seqnos, hkvPair.AddedAtSeqno)

		// should batch
		_, oldProof, err := t.eng.LookupVRFCache(ctx, tr, oldPeriod, hkvPair.Key)
		if err != nil {
			return 0, nil, err
		}
		oldProofs = append(oldProofs, oldProof)
	}

	st := time.Now()
	sk, pi, newProofs, err := t.cfg.ECVRF.StatefulRotate(oldSk, keys, oldProofs)
	if err != nil {
		return 0, nil, errors.Wrap(err, "stateful rotate")
	}
	runtime.GC()
	t.LastRotateVRFEl = time.Since(st)
	for i, hkvPair := range oldHKVPairs {
		t.rotateNewProofs[hkvPair.Key.String()] = newProofs[i]
	}

	err = t.eng.StoreVRFPrivateKey(ctx, tr, period, sk)
	if err != nil {
		return 0, nil, err
	}

	err = t.eng.StoreVRFRotationProof(ctx, tr, period, pi)
	if err != nil {
		return 0, nil, err
	}

	st = time.Now()
	// chunk
	i := 0
	runningSeqno := seqno
	for {
		if i > len(kvPairs)-1 {
			break
		}
		end := i + 100
		if end > len(kvPairs) {
			end = len(kvPairs)
		}
		chunkPairs := kvPairs[i:end]
		chunkSeqnos := seqnos[i:end]

		td, err = t.finalizeEpoch(ctx, tr, runningSeqno, period, sk, chunkPairs, chunkSeqnos, addOnsHash, false)
		if err != nil {
			return 0, nil, err
		}
		runningSeqno += 1
		i += 100

		if i%10000 == 0 {
			runtime.GC()
		}
	}

	t.LastRotateBuildEl = time.Since(st)
	t.rotateNewProofs = make(map[string][]byte)

	return seqno, td, nil
}

func (t *Tree) finalizeEpoch(ctx logger.ContextInterface, tr Transaction, seqno Seqno, period Period, sk *vrf.PrivateKey, kvps []KeyValuePair, seqnos []Seqno, addOnsHash []byte, fake bool) (td TransparencyDigest, err error) {
	hkvPairs, _, err := t.hideKVPairs(ctx, tr, period, sk, kvps, seqnos, fake)
	if err != nil {
		return nil, err
	}

	return t.finalizeEpochWithHiddenPairs(ctx, tr, seqno, period, sk.Public(), hkvPairs, seqnos, addOnsHash, fake)
}

func (t *Tree) finalizeEpochWithHiddenPairs(ctx logger.ContextInterface, tr Transaction, seqno Seqno, period Period, pk *vrf.PublicKey, hkvPairs []HiddenKeyValuePair, seqnos []Seqno, addOnsHash []byte, fake bool) (td TransparencyDigest, err error) {
	sortHiddenKeyValuePairsInPlace(hkvPairs)

	newBareRootHash, err := t.hashTreeRecursive(ctx, tr, seqno, period, t.cfg.GetRootPosition(), hkvPairs)
	if err != nil {
		return nil, err
	}

	newRootMetadata, err := t.makeRootMetadata(ctx, tr, seqno, period, newBareRootHash, pk, addOnsHash)
	if err != nil {
		return nil, err
	}
	if err = t.eng.StoreRoot(ctx, tr, newRootMetadata); err != nil {
		return nil, err
	}

	_, newRootHash, err := t.cfg.Encoder.EncodeAndHashGeneric(newRootMetadata)
	if err != nil {
		return nil, err
	}

	err = t.historyTree.Push(ctx, tr, newRootHash)
	if err != nil {
		return nil, err
	}

	td, err = t.historyTree.Root(ctx, tr)
	if err != nil {
		return nil, err
	}

	return td, nil
}

func (t *Tree) Debug(ctx logger.ContextInterface, tr Transaction, s Seqno, per Period) error {
	var err error
	_, err = t.eng.LookupLatestRoot(ctx, tr)
	if err != nil {
		return err
	}
	_, err = t.historyTree.Root(ctx, tr)
	if err != nil {
		return err
	}
	fmt.Println("Nodes")
	t.debug(ctx, tr, s, per, t.cfg.GetRootPosition())
	fmt.Println("Pairs")
	pairs, err := t.eng.LookupAllPairs(ctx, tr, s, per)
	if err != nil {
		return err
	}
	for _, pair := range pairs {
		fmt.Printf("%08b, %s\n", pair.Key, pair.EncodedValue)
	}
	return nil
}

func (t *Tree) debug(ctx logger.ContextInterface, tr Transaction, s Seqno, per Period, p *Position) error {
	h, err := t.eng.LookupNode(ctx, tr, s, per, p)
	var z = (*big.Int)(p)
	switch err.(type) {
	case NodeNotFoundError:
		return nil
	case nil:
		fmt.Printf("%08b: %x\n", z.Int64(), h)
	default:
		return err
	}
	for childIdx := ChildIndex(0); childIdx < ChildIndex(t.cfg.ChildrenPerNode); childIdx++ {
		childP := t.cfg.GetChild(p, childIdx)
		err = t.debug(ctx, tr, s, per, childP)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *Tree) upsertBinary(ctx logger.ContextInterface, tr Transaction, s Seqno, per Period,
	root *Position, hkvPairs []HiddenKeyValuePair) (ret []byte, err error) {

	if !(t.cfg.ChildrenPerNode == 2 && t.cfg.MaxValuesPerLeaf == 1) {
		return nil, fmt.Errorf("not binary with mvl=1")
	}

	if len(hkvPairs) == 0 {
		h, err := t.eng.LookupNode(ctx, tr, s, per, root)
		switch err.(type) {
		case nil:
			return h, nil
		case NodeNotFoundError:
			return nil, nil
		default:
			return nil, err
		}
	}

	var h []byte
	for _, pair := range hkvPairs {
		ret, err := t.upsertPair(ctx, tr, s, per, root, pair)
		if err != nil {
			return nil, err
		}
		h = ret
	}

	return h, nil
}

// root is depth 0
func queryLookup(lookup []PositionHashPair, depth int, sib bool) PositionHashPair {
	if depth == 0 && sib {
		panic("invalid use of query lookup")
	}
	s := 0
	if sib {
		s = 1
	}
	if depth == 0 {
		return lookup[0]
	}
	return lookup[depth*2+s-1]
}

func (t *Tree) findInsertionPoint(ctx logger.ContextInterface, tr Transaction, s Seqno, per Period,
	root *Position, opath []ChildIndex) ([]PositionHashPair, int, PositionHashPair, error) {
	depth := t.fastpathN

	return t.findInsertionPointHelper(ctx, tr, s, per, root, opath, depth)
}

var two = big.NewInt(2)

func getChildrenBinary(a *Position) (*big.Int, *big.Int) {
	left := new(big.Int)
	right := new(big.Int)
	left.Lsh((*big.Int)(a), 1)
	right.Set(left)
	right.Bits()[0] = right.Bits()[0] | big.Word(1)
	return left, right
}

func setChildrenBinary(a *Position, left *Position, right *Position) {
	(*big.Int)(left).Lsh((*big.Int)(a), 1)
	(*big.Int)(right).Set((*big.Int)(left))
	(*big.Int)(right).Bits()[0] = (*big.Int)(right).Bits()[0] | big.Word(1)
}

func (t *Tree) findInsertionPointHelper(ctx logger.ContextInterface, tr Transaction, s Seqno, per Period,
	root *Position, opath []ChildIndex, upto int) ([]PositionHashPair, int, PositionHashPair, error) {

	path := opath
	if upto > 0 {
		if upto >= len(path) {
			upto = len(path)
		}
		path = path[:upto]
	}

	if len(t.posBuf) < len(path)*2+1 {
		for i := 0; i < len(path)*2+1; i++ {
			t.posBuf = append(t.posBuf, (*Position)(new(big.Int)))
		}
	}

	targetn := root.Clone()
	targets := []*Position{targetn}
	counter := 0
	for i, _ := range path {
		childIndex := path[i]

		setChildrenBinary(targetn, t.posBuf[counter], t.posBuf[counter+1])
		if childIndex == 0 {
			targets = append(targets, t.posBuf[counter])
			targets = append(targets, t.posBuf[counter+1])
			targetn = t.posBuf[counter]
		} else {
			targets = append(targets, t.posBuf[counter+1])
			targets = append(targets, t.posBuf[counter])
			targetn = t.posBuf[counter+1]
		}
		counter += 2
	}

	lookup, err := t.eng.LookupNodes(ctx, tr, s, per, targets, true, true)
	if err != nil {
		return nil, 0, PositionHashPair{}, err
	}

	// Find the first nonexistent node on the path, which will be an ancestor of the node `pair` is inserted at.
	nodeLevel := 0
	php := queryLookup(lookup, 0, false)
	if len(php.Hash) != 0 {
		for i := 0; i < len(path); i++ {
			nodeLevel = i + 1
			php = queryLookup(lookup, nodeLevel, false)
			if len(php.Hash) == 0 {
				return lookup, nodeLevel, php, nil
			}
		}
	} else {
		return lookup, 0, php, nil
	}

	if upto != 0 {
		t.fastpathN += 5
		t.FastpathFallbacks += 1
		return t.findInsertionPointHelper(ctx, tr, s, per, root, opath, 0)
	}

	return nil, 0, PositionHashPair{}, fmt.Errorf("Failed to find nonexistent node")
}

func (t *Tree) upsertPair(ctx logger.ContextInterface, tr Transaction, s Seqno, per Period,
	root *Position, pair HiddenKeyValuePair) (ret []byte, err error) {
	k := pair.HiddenKey

	p, err := t.cfg.getDeepestPositionForKey(Key(k))
	if err != nil {
		return nil, err
	}

	lvl := t.cfg.getLevel(p)
	if t.insertPairPathBuf == nil || cap(t.insertPairPathBuf) < lvl {
		t.insertPairPathBuf = make([]ChildIndex, lvl)
	} else {
		t.insertPairPathBuf = t.insertPairPathBuf[:lvl]
	}
	// Query all nodes on path along with siblings.
	path := t.cfg.positionToChildIndexPathPlace(p, t.insertPairPathBuf)

	// reverse reversed path
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	path = path[t.cfg.getLevel(root):] // only for arity 2:

	lookup, nodeLevel, php, err := t.findInsertionPoint(ctx, tr, s, per, root, path)
	if err != nil {
		return nil, err
	}

	node := &php.Position
	par := node.Clone()
	var isInternal bool
	if node.Equals(root) {
		isInternal = false
	} else {
		par = t.cfg.getParent(node)
		// par is either an internal node or a leaf.
		sibphp := queryLookup(lookup, nodeLevel, true)
		isInternal = len(sibphp.Hash) != 0
	}

	var roothash []byte

	if isInternal {
		// We can insert the pair directly at the nonexistent node, and there are no other pairs to consider.
		targethash, err := t.insertAtEndBinaryMVL1(ctx, tr, s, per, node, []HiddenKeyValuePair{pair})
		if err != nil {
			return nil, err
		}
		roothash, err = t.rehashUpBinaryCached(ctx, tr, s, per, root, node, targethash, lookup)
		if err != nil {
			return nil, err
		}
	} else {
		// The pair will exist underneath the nonexistent node, however, since par is a leaf,
		// and pairs stored at par will have to be moved as well. Because there is at most 1 pair per leaf,
		// we have at most 2 pairs to consider. We need to recurse down until we can place the two pairs
		// in different leaves, in case they share a common prefix beyond par.
		// In this implementation, empty leaves don't exist, so there will be exactly 2 pairs to consider.

		existingKevpairs, err := t.eng.LookupPairsUnderPosition(ctx, tr, s, per, par)
		switch err.(type) {
		case nil:
		case KeyNotFoundError:
			existingKevpairs = nil
		default:
			return nil, err
		}
		if len(existingKevpairs) > 1 {
			return nil, fmt.Errorf("wrong number of pairs at leaf %v; %d > 1", par, len(existingKevpairs))
		}

		kevpairs := []HiddenKeyValuePair{pair}

		if len(existingKevpairs) > 0 {
			existingKevpair := existingKevpairs[0]
			if existingKevpair.HiddenKey.Equal(pair.HiddenKey) {
				return nil, fmt.Errorf("duplicate key inserted into merkle tree")
			}
			kevpairs = append(kevpairs, existingKevpair)
		}

		parhash, err := t.insertAtEndBinaryMVL1(ctx, tr, s, per, par, kevpairs)
		if err != nil {
			return nil, err
		}

		roothash, err = t.rehashUpBinaryCached(ctx, tr, s, per, root, par, parhash, lookup)
		if err != nil {
			return nil, err
		}
	}

	if err = t.eng.StorePairs(ctx, tr, s, per, []HiddenKeyValuePair{pair}); err != nil {
		return nil, err
	}

	return roothash, nil
}

func (t *Tree) rehashUpBinaryCached(ctx logger.ContextInterface, tr Transaction, s Seqno, per Period, root *Position, p *Position, h []byte, lookup []PositionHashPair) ([]byte, error) {
	t.rstpathbuf(p)
	t.cfg.positionToChildIndexPathPlace(p, t.pathBuf)

	if p.Equals(root) {
		return h, nil
	}
	if t.cfg.ChildrenPerNode != 2 {
		return nil, fmt.Errorf("must be binary tree")
	}
	siblingPositions := t.makeSibPos()
	for !p.Equals(root) {
		var siblingPosition big.Int
		siblingPosition.SetBit((*big.Int)(p), 0, 1-(*big.Int)(p).Bit(0))
		siblingPositions = append(siblingPositions, Position(siblingPosition))
		t.cfg.updateToParent(p)
	}
	// t.Depths = append(t.Depths, len(siblingPositions))

	toStore := t.maketostore(len(siblingPositions) - 1)
	for i, siblingPos := range siblingPositions {
		siblingPosition := siblingPos.Clone()
		siblingPhp := queryLookup(lookup, len(siblingPositions)-i, true)
		node := t.makenode(2)
		idx := t.pathBuf[i]
		node.INodes[idx] = h
		node.INodes[1-idx] = siblingPhp.Hash
		h = node.HashINodes()
		t.cfg.updateToParent(siblingPosition)
		toStore = append(toStore, PositionHashPair{Position: *siblingPosition, Hash: h})
	}

	if len(toStore) > 0 {
		err := t.eng.StoreNodes(ctx, tr, s, per, toStore)
		if err != nil {
			return nil, err
		}
	}
	return h, nil
}

func (t *Tree) hashTreeRecursive(ctx logger.ContextInterface, tr Transaction, s Seqno, per Period,
	root *Position, hkvPairs []HiddenKeyValuePair) (ret []byte, err error) {

	if t.cfg.ChildrenPerNode == 2 && t.cfg.MaxValuesPerLeaf == 1 {
		return t.upsertBinary(ctx, tr, s, per, root, hkvPairs)
	}

	return nil, fmt.Errorf("unimplemented")
}

func (t *Tree) makeSibPos() []Position {
	if t.sibpos == nil {
		t.sibpos = make([]Position, 0, 6)
	}
	t.sibpos = t.sibpos[:0]
	return t.sibpos
}

func (t *Tree) maketostore(n int) []PositionHashPair {
	if t.tostore == nil {
		t.tostore = make([]PositionHashPair, 0, 20)
	}
	t.tostore = t.tostore[:0]
	return t.tostore
}

func (t *Tree) makenode(n int) *Node {
	if t.nodebuf == nil {
		t.nodebuf = &Node{INodes: make([][]byte, 2)}
	}
	return t.nodebuf
}

func (t *Tree) rstpathbuf(p *Position) {
	lvl := t.cfg.getLevel(p)
	if t.pathBuf == nil || cap(t.pathBuf) < lvl {
		t.pathBuf = make([]ChildIndex, lvl)
	} else {
		t.pathBuf = t.pathBuf[:lvl]
	}
}

func (t *Tree) insertAtEndBinaryMVL1(ctx logger.ContextInterface, tr Transaction, s Seqno,
	per Period, p *Position, hkvPairs []HiddenKeyValuePair) (ret []byte, err error) {

	if len(hkvPairs) == 0 {
		return nil, nil
	} else if len(hkvPairs) <= t.cfg.MaxValuesPerLeaf {
		err = t.makeAndStoreLeaf(ctx, tr, s, per, p, hkvPairs, &ret)
		if err != nil {
			return nil, err
		}
		return ret, nil
	}

	sort.Slice(hkvPairs, func(i, j int) bool {
		return hkvPairs[i].HiddenKey.Cmp(hkvPairs[j].HiddenKey) <= 0
	})

	// There is at most t.cfg.MaxValuesPerLeaf+1 by assumption.
	// However, it is not necessarily the case that the direct children can accommodate all the
	// pairs. We need to descend until the amount of pairs on the path is <=
	// t.cfg.MaxValuesPerLeaf, and then update the hashes.

	// Since binary and max values per leaf is 1, we have 2 pairs.
	// They have a common prefix at p. We need to iterate child by child while they
	// have the same path, and then make two leaves at the last leaf they share.

	// require len(hkvPairs) == 2

	k1 := hkvPairs[0].HiddenKey
	k2 := hkvPairs[1].HiddenKey
	// require k1 != k2
	var directions []int
	var lefthash []byte
	var righthash []byte
	for {
		left := t.cfg.GetChild(p, 0)
		right := t.cfg.GetChild(p, 1)
		if left.isOnPathToKey(Key(k1)) && left.isOnPathToKey(Key(k2)) {
			p = left
			directions = append(directions, 0)
		} else if right.isOnPathToKey(Key(k1)) && right.isOnPathToKey(Key(k2)) {
			p = right
			directions = append(directions, 1)
		} else if left.isOnPathToKey(Key(k1)) {
			lefthash, err = t.insertAtEndBinaryMVL1(ctx, tr, s, per, left, []HiddenKeyValuePair{hkvPairs[0]})
			if err != nil {
				return nil, err
			}
			righthash, err = t.insertAtEndBinaryMVL1(ctx, tr, s, per, right, []HiddenKeyValuePair{hkvPairs[1]})
			if err != nil {
				return nil, err
			}
			break
		} else {
			lefthash, err = t.insertAtEndBinaryMVL1(ctx, tr, s, per, left, []HiddenKeyValuePair{hkvPairs[1]})
			if err != nil {
				return nil, err
			}
			righthash, err = t.insertAtEndBinaryMVL1(ctx, tr, s, per, right, []HiddenKeyValuePair{hkvPairs[0]})
			if err != nil {
				return nil, err
			}
			break
		}
	}
	var phps []PositionHashPair
	node := Node{INodes: [][]byte{lefthash, righthash}}
	h := node.HashINodes()
	phps = append(phps, PositionHashPair{Position: *p, Hash: h})
	for i := range directions {
		p = t.cfg.getParent(p)
		direction := directions[len(directions)-1-i]
		if direction == 0 {
			node = Node{INodes: [][]byte{h, nil}}
		} else {
			node = Node{INodes: [][]byte{nil, h}}
		}
		h = node.HashINodes()
		phps = append(phps, PositionHashPair{Position: *p, Hash: h})
	}

	err = t.eng.StoreNodes(ctx, tr, s, per, phps)
	if err != nil {
		return nil, err
	}

	return h, nil
}
func HashPair(pair HiddenKeyValuePair) []byte {
	h := sha256.New()
	h.Write(pair.Key)
	seqnob := make([]byte, 4)
	binary.BigEndian.PutUint32(seqnob, uint32(pair.AddedAtSeqno))
	h.Write(seqnob)
	h.Write(pair.HiddenKey)
	h.Write(pair.Entropy)
	h.Write(pair.EncodedValue) // last to prevent collision
	return h.Sum(nil)
}

// makeKeyHashPairsFromKeyValuePairs preserves ordering
func (t *Tree) makeKeyHashPairsFromKeyValuePairs(hkvpairs []HiddenKeyValuePair, node *Node) (err error) {
	if cap(node.LeafHashes) < len(hkvpairs) {
		node.LeafHashes = make([]KeyHashPair, len(hkvpairs))
	}
	node.LeafHashes = node.LeafHashes[:len(hkvpairs)]

	for i, hkvpair := range hkvpairs {
		// err = t.cfg.Encoder.HashGeneric(hkvpair, &node.LeafHashes[i].Hash)
		// if err != nil {
		// 	return err
		// }
		node.LeafHashes[i].Hash = HashPair(hkvpair)
		node.LeafHashes[i].HiddenKey = hkvpair.HiddenKey
		node.LeafHashes[i].AddedAtSeqno = hkvpair.AddedAtSeqno
	}
	return nil
}

func (t *Tree) makeAndStoreLeaf(ctx logger.ContextInterface, tr Transaction, s Seqno, per Period, p *Position, sortedHkvPairs []HiddenKeyValuePair, ret *[]byte) (err error) {
	if len(sortedHkvPairs) > t.cfg.MaxValuesPerLeaf {
		return fmt.Errorf("can only store %d values in leaf, got %d", t.cfg.MaxValuesPerLeaf, len(sortedHkvPairs))
	}

	err = t.makeKeyHashPairsFromKeyValuePairs(sortedHkvPairs, &t.bufLeaf)
	if err != nil {
		return err
	}

	// if err = t.cfg.Encoder.HashGeneric(t.bufLeaf, ret); err != nil {
	// 	return err
	// }

	*ret = t.bufLeaf.HashLeafHashes()

	if err = t.eng.StoreNodes(ctx, tr, s, per, []PositionHashPair{PositionHashPair{Position: *p, Hash: *ret}}); err != nil {
		return err
	}
	return nil
}

// A MerkleInclusionProof proves that a specific key value pair is stored in a
// merkle tree, given the RootMetadata hash of such tree. It can also be used to
// prove that a specific key is not part of the tree (we call this an exclusion
// or absence proof)
type MerkleInclusionProof struct {
	_struct struct{} `codec:",toarray"` //nolint
	// When this struct is used as an exclusion proof, OtherPairsInLeaf is set
	// to nil if the proof ends at an internal node, and set to a slice of
	// length 0 or more if the proof ends at a (possibly empty) leaf node. In
	// particular, a tree with no keys is encoded with the root being the only
	// (empty leaf) node.
	OtherPairsInLeaf []KeyHashPair `codec:"l"`
	AddedAtSeqno     Seqno         `codec:"z"`
	// SiblingHashesOnPath are ordered by level from the farthest to the closest
	// to the root, and lexicographically within each level.
	SiblingHashesOnPath [][]byte     `codec:"s"`
	RootMetadataNoHash  RootMetadata `codec:"e"`
	HtSiblings          [][]byte     `codec:"h"`
	Entropy             Entropy      `codec:"e"`
	VRFProof            []byte       `codec:"v"`
}

// A MerkleExtensionProof proves, given the RootMetadata hashes of two merkle
// trees and their respective Seqno values, that: - the two merkle trees have
// the expected Seqno values, - the most recent merkle tree "points back" to the
// least recent one through appropriate nodes on the history tree allowing
// a reconstruction of the later history tree root hash.
// The indices for each hash can be deterministically computed given the two
// RootMetadata seqnos in context.
type MerkleExtensionProof struct {
	_struct               struct{} `codec:",toarray"` //nolint
	HistoryTreeNodeHashes [][]byte `codec:"h"`
}

// This type orders positionHashPairs by position, more specificelly first by
// level descending (nodes with higher level first) and then within each level
// in ascending order. This is the order required by the merkle proof verifier
// to easily reconstruct a path.
type PosHashPairsInMerkleProofOrder []PositionHashPair

func (p PosHashPairsInMerkleProofOrder) Len() int {
	return len(p)
}

func (p PosHashPairsInMerkleProofOrder) Less(i, j int) bool {
	return p[i].Position.CmpInMerkleProofOrder(&(p[j].Position)) < 0
}

func (p PosHashPairsInMerkleProofOrder) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

var _ sort.Interface = PosHashPairsInMerkleProofOrder{}

func (t *Tree) QueryKeyUnsafe(ctx logger.ContextInterface, tr Transaction, epno Seqno, k Key) (bool, interface{}, error) {
	rootMetadata, err := t.eng.LookupRoot(ctx, tr, epno)
	if err != nil {
		return false, nil, err
	}

	hiddenKey, _, err := t.lookupKeyOrHide(ctx, tr, rootMetadata.Period, epno, k)
	if err != nil {
		return false, nil, err
	}

	kevp, err := t.eng.LookupPair(ctx, tr, rootMetadata.Period, epno, hiddenKey)
	switch err.(type) {
	case nil:
		valContainer := t.cfg.ConstructValueContainer()
		err = t.cfg.Encoder.Decode(&valContainer, kevp.EncodedValue)
		if err != nil {
			return false, nil, err
		}
		return true, valContainer, nil
	case KeyNotFoundError:
		return false, nil, nil
	default:
		return false, nil, err
	}
}

func (t *Tree) QueryKey(ctx logger.ContextInterface, tr Transaction, epno Seqno, k Key) (bool, interface{}, MerkleInclusionProof, error) {
	rootMetadata, err := t.eng.LookupRoot(ctx, tr, epno)
	if err != nil {
		return false, nil, MerkleInclusionProof{}, err
	}

	val, pf, err := t.getEncodedValueWithInclusionProofOrExclusionProof(ctx, tr, rootMetadata, k)
	if err != nil {
		return false, nil, MerkleInclusionProof{}, err
	}
	valContainer := t.cfg.ConstructValueContainer()
	if val != nil {
		err = t.cfg.Encoder.Decode(&valContainer, val)
		if err != nil {
			return false, nil, MerkleInclusionProof{}, err
		}
	}
	return val != nil, valContainer, pf, nil
}

func (t *Tree) lookupKeyOrHide(ctx logger.ContextInterface, tr Transaction, per Period, s Seqno, k Key) (HiddenKey, []byte, error) {
	hiddenKey, vrf_proof, err := t.eng.LookupVRFCache(ctx, tr, per, k)
	if err != nil {
		return nil, nil, err
	}
	if hiddenKey != nil {
		return hiddenKey, vrf_proof, nil
	}

	vrfSk, err := t.eng.LookupVRFPrivateKey(ctx, tr, per)
	if err != nil {
		return nil, nil, err
	}

	hiddenKey, vrfProof, err := t.hideKey(vrfSk, k, false)
	if err != nil {
		return nil, nil, err
	}
	// this happens only when exclusion proof is initially requested
	f := func() {
		err = t.eng.StoreVRFCache(ctx, tr, per, []Key{k}, []HiddenKey{hiddenKey}, [][]byte{vrfProof})

		if err != nil {
			fmt.Printf("Failed to store vrf: %s\n", err)
			// 	return nil, nil, err
		}
	}
	f()
	// _, ok := t.eng.(*InMemoryStorageEngine)
	// if ok {
	// 	f()
	// } else {
	// 	go f()
	// }

	return hiddenKey, vrfProof, nil
}

// if the key is not in the tree, this function returns a nil value, a proof
// which certifies that and no error.
func (t *Tree) getEncodedValueWithInclusionProofOrExclusionProof(ctx logger.ContextInterface, tr Transaction,
	rootMetadata RootMetadata, k Key) (val EncodedValue, proof MerkleInclusionProof, err error) {

	hiddenKey, vrf_proof, err := t.lookupKeyOrHide(ctx, tr, rootMetadata.Period, rootMetadata.Seqno, k)
	if err != nil {
		return nil, MerkleInclusionProof{}, err
	}

	if len(hiddenKey) != t.cfg.KeysByteLength {
		return nil, MerkleInclusionProof{}, fmt.Errorf("The supplied key has the wrong length: exp %v, got %v", t.cfg.KeysByteLength, len(hiddenKey))
	}

	proof.VRFProof = vrf_proof

	s := rootMetadata.Seqno
	proof.RootMetadataNoHash = rootMetadata
	// clear up hash to make the proof smaller.
	proof.RootMetadataNoHash.BareRootHash = nil

	var siblingPosHashPairs []PositionHashPair
	needMore := true
	for curr := 1; needMore && curr <= t.cfg.MaxDepth; curr += t.step + 1 {
		// The first element is the position at level curr+step on the path from
		// the root to k (on a complete tree). The next ones are all the
		// necessary siblings at levels from curr+step to curr (both included)
		// on such path.
		deepestAndCurrSiblingPositions := t.cfg.getDeepestPositionAtLevelAndSiblingsOnPathToKey(Key(hiddenKey), curr+t.step, curr)
		var ret []*Position
		for _, sib := range deepestAndCurrSiblingPositions {
			sib := sib
			ret = append(ret, &sib)
		}
		_deepestAndCurrSiblings, err := t.eng.LookupNodes(ctx, tr, s, rootMetadata.Period, ret, false, false)
		var deepestAndCurrSiblings = make([]PositionHashPair, len(_deepestAndCurrSiblings))
		copy(deepestAndCurrSiblings, _deepestAndCurrSiblings)
		if err != nil {
			return nil, MerkleInclusionProof{}, err
		}

		sort.Sort(PosHashPairsInMerkleProofOrder(deepestAndCurrSiblings))

		var currSiblings []PositionHashPair
		// if we found a PositionHashPair corresponding to the first element in
		// deepestAndCurrSiblingPositions, it means the path might be deeper and we
		// need to fetch more siblings.
		candidateDeepest := len(deepestAndCurrSiblings)
		if len(deepestAndCurrSiblings) > 0 {
			candidateDeepest = sort.Search(len(deepestAndCurrSiblings), func(i int) bool {
				return deepestAndCurrSiblings[i].Position.CmpInMerkleProofOrder(&deepestAndCurrSiblingPositions[0]) >= 0
			})
		}
		if candidateDeepest < len(deepestAndCurrSiblings) && deepestAndCurrSiblings[candidateDeepest].Position.Equals(&deepestAndCurrSiblingPositions[0]) {
			currSiblings = deepestAndCurrSiblings[:candidateDeepest]
			currSiblings = append(currSiblings, deepestAndCurrSiblings[candidateDeepest+1:]...)
		} else {
			currSiblings = deepestAndCurrSiblings
			needMore = false
		}
		siblingPosHashPairs = append(currSiblings, siblingPosHashPairs...)
	}
	var leafLevel int
	if len(siblingPosHashPairs) == 0 {
		// If there are no siblings, the key must be stored on the root
		leafLevel = 0
	} else {
		// The level of the first sibling equals the level of the leaf node for the
		// key we are producing the proof for.
		leafLevel = t.cfg.getLevel(&(siblingPosHashPairs[0].Position))
	}

	deepestPosition, err := t.cfg.getDeepestPositionForKey(Key(hiddenKey))
	if err != nil {
		return nil, MerkleInclusionProof{}, err
	}
	leafPos := t.cfg.getParentAtLevel(deepestPosition, uint(leafLevel))

	proof.SiblingHashesOnPath = make([][]byte, leafLevel*(t.cfg.ChildrenPerNode-1))
	leafChildIndexes := t.cfg.positionToChildIndexPath(leafPos)
	// Flatten the siblingPosHashPairs Hashes into a []Hash.
	for _, pos := range siblingPosHashPairs {
		if t.cfg.getDeepestChildIndex(&pos.Position) < leafChildIndexes[leafLevel-t.cfg.getLevel(&pos.Position)] {
			proof.SiblingHashesOnPath[(leafLevel-t.cfg.getLevel(&pos.Position))*(t.cfg.ChildrenPerNode-1)+int(t.cfg.getDeepestChildIndex(&pos.Position))] = pos.Hash
		} else {
			proof.SiblingHashesOnPath[(leafLevel-t.cfg.getLevel(&pos.Position))*(t.cfg.ChildrenPerNode-1)+int(t.cfg.getDeepestChildIndex(&pos.Position))-1] = pos.Hash
		}
	}

	var kevps []HiddenKeyValuePair

	// We have two cases: either the node at leafPos is actually a leaf
	// (which might or not contain the key which we are trying to look up),
	// or such node does not exist at all (which happens only if the key we
	// are looking up is not part of the tree at that seqno).

	_, err = t.eng.LookupNode(ctx, tr, s, rootMetadata.Period, leafPos)
	if err != nil {
		// NodeNotFoundError is ignored as the inclusion proof we
		// produce will prove that the key is not in the tree.
		if _, nodeNotFound := err.(NodeNotFoundError); !nodeNotFound {
			return nil, MerkleInclusionProof{}, err
		}
	} else {

		if t.cfg.MaxValuesPerLeaf == 1 {
			kevp, err := t.eng.LookupPair(ctx, tr, rootMetadata.Period, s, hiddenKey)
			if err != nil {
				// KeyNotFoundError is ignored as the inclusion proof we
				// produce will prove that the key is not in the tree.
				if _, keyNotFound := err.(KeyNotFoundError); !keyNotFound {
					return nil, MerkleInclusionProof{}, err
				}
			} else {
				kevps = append(kevps, kevp)
			}
		}

		// if len(kevps)>0, then MaxValuesPerLeaf == 1 and we found the key we
		// are looking for, so there is no need to look for other keys under
		// leafPos.
		if len(kevps) == 0 {
			// Lookup hashes of key value pairs stored at the same leaf.
			// These pairs are ordered by key.
			kevps, err = t.eng.LookupPairsUnderPosition(ctx, tr, s, rootMetadata.Period, leafPos)
			if err != nil {
				// KeyNotFoundError is ignored. This would happen when we are
				// trying to produce an absence proof on an empty tree: there
				// would be a leaf node containing no keys.
				if _, keyNotFound := err.(KeyNotFoundError); !keyNotFound {
					return nil, MerkleInclusionProof{}, err
				}
				kevps = make([]HiddenKeyValuePair, 0)
			}
		}
	}

	// OtherPairsInLeaf will have length equal to kevps - 1  in an inclusion
	// proof, and kevps in an absence proof.
	if kevps != nil {
		proof.OtherPairsInLeaf = make([]KeyHashPair, 0, len(kevps))
	}

	// TODO for exclusion proof, why not use KeyHash pairs in leaf from the  LookupNode to populate OtherPairsInLeaf? Rather than LookupPairs and then reconstruct

	for _, kevpi := range kevps {
		if kevpi.HiddenKey.Equal(hiddenKey) {
			val = kevpi.EncodedValue
			proof.Entropy = kevpi.Entropy
			proof.AddedAtSeqno = kevpi.AddedAtSeqno
			continue
		}

		hash := HashPair(kevpi)
		proof.OtherPairsInLeaf = append(proof.OtherPairsInLeaf, KeyHashPair{HiddenKey: kevpi.HiddenKey, Hash: hash, AddedAtSeqno: kevpi.AddedAtSeqno})
	}

	idxs := auditProofIndices(rootMetadata.Seqno, rootMetadata.Seqno)
	htSiblings, err := t.historyTree.Gets(ctx, tr, idxs)
	if err != nil {
		return nil, MerkleInclusionProof{}, err
	}
	proof.HtSiblings = htSiblings

	return val, proof, nil
}

func (t *Tree) GetExtensionProof(ctx logger.ContextInterface, tr Transaction, fromSeqno, toSeqno Seqno) (proof MerkleExtensionProof, err error) {
	if fromSeqno == toSeqno {
		return MerkleExtensionProof{}, nil
	}

	indices := consistencyProofIndices(fromSeqno, toSeqno)
	historyTreeNodeHashes, err := t.historyTree.Gets(ctx, tr, indices)
	if err != nil {
		return proof, err
	}
	return MerkleExtensionProof{HistoryTreeNodeHashes: historyTreeNodeHashes}, nil
}

// GetLatestRoot returns the latest RootMetadata which was stored in the
// tree (and its Hash and Seqno). If no such record was stored yet,
// GetLatestRoot returns 0 as a Seqno and a NoLatestRootFound error.
func (t *Tree) GetLatestRoot(ctx logger.ContextInterface, tr Transaction) (s Seqno, root RootMetadata, td TransparencyDigest, err error) {
	rootMd, err := t.eng.LookupLatestRoot(ctx, tr)
	if err != nil {
		return 0, RootMetadata{}, nil, err
	}
	td, err = t.historyTree.Root(ctx, tr)
	if err != nil {
		return 0, RootMetadata{}, nil, err
	}
	return rootMd.Seqno, rootMd, td, nil
}

func (t *Tree) HistoryTree() *LBBMT {
	return t.historyTree
}
