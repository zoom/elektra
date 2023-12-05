package merkle

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/mvkdcrypto/mvkd/demo/bst"
	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/vrf"
)

func EmptyKVPR(hk HiddenKey) *KVPRecord {
	return &KVPRecord{kevp: HiddenKeyValuePair{HiddenKey: hk}}
}

func (kvpr *KVPRecord) Less(kvpr2 bst.Interface) bool {
	kvpr3 := kvpr2.(*KVPRecord)
	return kvpr.kevp.HiddenKey.Cmp(kvpr3.kevp.HiddenKey) <= 0
}

type VRFEntry struct {
	value HiddenKey
	proof []byte
}

// In memory StorageEngine implementation, used for tests. It ignores
// Transaction arguments, so it can't be used for concurrency tests.
type InMemoryStorageEngine struct {
	Roots map[Seqno]RootMetadata

	KeyMap   map[Period]map[string]HiddenKey
	VRFCache *sync.Map

	SortedKVPRs map[Period]*bst.Tree
	Nodes       map[Period]map[string]*NodeRecord

	VRFPrivateKeys map[Period]*vrf.PrivateKey

	VRFRotationProofs map[Period]vrf.RotationProof
	ArrayDat          map[int][]byte
	Lc                int

	phBuf []PositionHashPair

	// used to make prefix queries efficient. Not otherwise necessary
	//PositionToKeys map[string](map[string]bool)
	cfg Config
}

// var _ StorageEngine = &InMemoryStorageEngine{}

type SortedKVPR []*KVPRecord

func (s SortedKVPR) Len() int {
	return len(s)
}

func (s SortedKVPR) Less(i, j int) bool {
	return s[i].kevp.HiddenKey.Cmp(s[j].kevp.HiddenKey) < 0
}

func (s SortedKVPR) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

var _ sort.Interface = SortedKVPR{}

type NodeRecord struct {
	p    Position
	s    Seqno
	h    []byte
	next *NodeRecord
}

type KVPRecord struct {
	kevp HiddenKeyValuePair
	s    Seqno
	next *KVPRecord
}

func NewInMemoryStorageEngine(cfg Config) *InMemoryStorageEngine {
	i := InMemoryStorageEngine{}
	i.Roots = make(map[Seqno]RootMetadata)
	i.KeyMap = make(map[Period]map[string]HiddenKey)
	i.VRFCache = new(sync.Map)
	i.SortedKVPRs = make(map[Period]*bst.Tree)
	i.Nodes = make(map[Period]map[string]*NodeRecord)
	i.cfg = cfg
	i.VRFRotationProofs = make(map[Period]vrf.RotationProof)
	i.VRFPrivateKeys = make(map[Period]*vrf.PrivateKey)
	i.ArrayDat = make(map[int][]byte)
	return &i
}

func (i *InMemoryStorageEngine) findKVPR(p Period, k HiddenKey) *KVPRecord {
	m := i.SortedKVPRs[p]
	if m == nil {
		return nil
	}
	n := m.Search(EmptyKVPR(k))
	if n == nil {
		return nil
	}
	r := n.Key.(*KVPRecord)
	return r
}

func (i *InMemoryStorageEngine) StoreVRFCache(c logger.ContextInterface, t Transaction,
	p Period, key []Key, hk []HiddenKey, proof [][]byte) error {
	m, ok := i.VRFCache.Load(p)
	if !ok {
		m = new(sync.Map)
		i.VRFCache.Store(p, m)
	}
	mmap := m.(*sync.Map)
	for j, k := range key {
		mmap.Store(k.String(), VRFEntry{hk[j], proof[j]})
	}
	return nil
}

func (i *InMemoryStorageEngine) LookupVRFCache(c logger.ContextInterface, t Transaction,
	per Period, key Key) (HiddenKey, []byte, error) {
	m, ok := i.VRFCache.Load(per)
	if !ok {
		return nil, nil, nil
	}
	mmap := m.(*sync.Map)
	entry, ok := mmap.Load(key.String())
	if !ok {
		return nil, nil, nil
	}
	vrfentry := entry.(VRFEntry)
	if vrfentry.value == nil {
		return nil, nil, nil
	}
	return vrfentry.value, vrfentry.proof, nil
}

func (i *InMemoryStorageEngine) StorePairs(c logger.ContextInterface, t Transaction,
	s Seqno, p Period, kevps []HiddenKeyValuePair) error {

	for _, kevp := range kevps {
		if i.KeyMap[p] == nil {
			i.KeyMap[p] = make(map[string]HiddenKey)
		}
		i.KeyMap[p][string(kevp.Key)] = kevp.HiddenKey

		nd := bst.NewNode(&KVPRecord{kevp: kevp, s: s, next: nil})
		if i.SortedKVPRs[p] == nil {
			i.SortedKVPRs[p] = bst.New(nd)
		} else {
			i.SortedKVPRs[p].Insert(nd)
		}
	}
	return nil
}

func (i *InMemoryStorageEngine) StoreNodes(c logger.ContextInterface, t Transaction, s Seqno, p Period, phps []PositionHashPair) error {
	for _, php := range phps {
		err := i.storeNode(c, t, s, p, &php.Position, php.Hash)
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *InMemoryStorageEngine) storeNode(c logger.ContextInterface, t Transaction, s Seqno, per Period, p *Position, h []byte) error {
	strKey := p.AsString()

	if len(i.Nodes[per]) == 0 {
		i.Nodes[per] = make(map[string]*NodeRecord)
	}

	oldNodeRec := i.Nodes[per][strKey]
	newp := p.Clone()
	i.Nodes[per][strKey] = &NodeRecord{s: s, p: *newp, h: h, next: oldNodeRec}
	if oldNodeRec != nil && oldNodeRec.s > s { // > instead of >= to allow updating same node multiple times in a build
		return errors.New("engine does not support out of order insertions")
	}
	return nil
}

func (i *InMemoryStorageEngine) StoreRoot(c logger.ContextInterface, t Transaction, r RootMetadata) error {
	i.Roots[r.Seqno] = r
	return nil
}

func (i *InMemoryStorageEngine) LookupLatestRoot(c logger.ContextInterface, t Transaction) (RootMetadata, error) {
	if len(i.Roots) == 0 {
		return RootMetadata{}, NewNoLatestRootFoundError()
	}
	max := Seqno(0)
	for k := range i.Roots {
		if k > max {
			max = k
		}
	}
	return i.Roots[max], nil
}

func (i *InMemoryStorageEngine) LookupRoot(c logger.ContextInterface, t Transaction, s Seqno) (RootMetadata, error) {
	r, found := i.Roots[s]
	if found {
		return r, nil
	}
	return RootMetadata{}, NewInvalidSeqnoError(s, fmt.Errorf("No root at seqno %v", s))
}

func (i *InMemoryStorageEngine) LookupNode(c logger.ContextInterface, t Transaction, s Seqno, per Period, p *Position) ([]byte, error) {
	node, found := i.Nodes[per][string(p.GetBytes())]
	if !found {
		return nil, NewNodeNotFoundError()
	}
	for ; node != nil; node = node.next {
		if node.s <= s {
			return node.h, nil
		}
	}
	return nil, NewNodeNotFoundError()
}

// func (i *InMemoryStorageEngine) LookupNodes(c logger.ContextInterface, t Transaction, s Seqno, per Period, positions []Position, includeNils bool) (res []PositionHashPair, err error) {
// 	i.LookupNodesPlace(c, t, s, per, positions, includeNils, res)
// 	return res
// }

func (i *InMemoryStorageEngine) LookupNodes(c logger.ContextInterface, t Transaction, s Seqno, per Period, positions []*Position, includeNils bool, latest bool) (res []PositionHashPair, err error) {
	i.Lc += len(positions)

	if i.phBuf == nil {
		i.phBuf = make([]PositionHashPair, 0, len(positions))
	}
	i.phBuf = i.phBuf[:0]

	for _, p := range positions {
		h, err := i.LookupNode(c, t, s, per, p)

		if includeNils {
			switch err.(type) {
			case nil:
				i.phBuf = append(i.phBuf, PositionHashPair{Position: *p, Hash: h})
			case NodeNotFoundError:
				i.phBuf = append(i.phBuf, PositionHashPair{Position: *p, Hash: nil})
			default:
				return nil, err
			}
		} else {
			switch err.(type) {
			case nil:
				i.phBuf = append(i.phBuf, PositionHashPair{Position: *p, Hash: h})
			case NodeNotFoundError:
			default:
				return nil, err
			}
		}
	}

	// Shuffle the result to catch bugs that happen when ordering is different.
	// rand.Shuffle(len(res), func(i, j int) { res[i], res[j] = res[j], res[i] })

	return i.phBuf, nil
}

func (i *InMemoryStorageEngine) LookupPair(c logger.ContextInterface, t Transaction, per Period, s Seqno, k HiddenKey) (HiddenKeyValuePair, error) {
	kvpr := i.findKVPR(per, k)
	if kvpr == nil {
		return HiddenKeyValuePair{}, NewKeyNotFoundError()
	}
	for ; kvpr != nil; kvpr = kvpr.next {
		if kvpr.s <= s {
			return kvpr.kevp, nil
		}
	}
	return HiddenKeyValuePair{}, NewKeyNotFoundError()
}

func (i *InMemoryStorageEngine) LookupPairsUnderPosition(ctx logger.ContextInterface, t Transaction, s Seqno,
	per Period, p *Position) (kvps []HiddenKeyValuePair, err error) {
	bstree := i.SortedKVPRs[per]
	minKey, maxKey := i.cfg.GetKeyIntervalUnderPosition(p)
	kvpsI := bstree.SearchRange(EmptyKVPR(HiddenKey(minKey)), EmptyKVPR(HiddenKey(maxKey)))
	for _, kvpi := range kvpsI {
		kvpr := kvpi.Key.(*KVPRecord)
		for ; kvpr != nil; kvpr = kvpr.next {
			if kvpr.s <= s {
				kvps = append(kvps, kvpr.kevp)
				break
			}
		}
	}
	return kvps, nil
}

// LookupAllPairs returns all the keys and encoded values at the specified Seqno.
func (i *InMemoryStorageEngine) LookupAllPairs(ctx logger.ContextInterface, t Transaction,
	s Seqno, per Period) (kevps []HiddenKeyValuePair, err error) {
	for _, _kvpr := range i.SortedKVPRs[per].TraverseInOrder() {
		kvpr := _kvpr.Key.(*KVPRecord)
		for ; kvpr != nil; kvpr = kvpr.next {
			if kvpr.s <= s {
				kevps = append(kevps, kvpr.kevp)
				break
			}
		}
	}
	return kevps, nil
}

func (i *InMemoryStorageEngine) StoreVRFPrivateKey(ctx logger.ContextInterface, t Transaction, p Period, sk *vrf.PrivateKey) (err error) {
	i.VRFPrivateKeys[p] = sk
	return nil
}

func (i *InMemoryStorageEngine) StoreVRFRotationProof(ctx logger.ContextInterface, t Transaction, p Period, pi vrf.RotationProof) error {
	i.VRFRotationProofs[p] = pi
	return nil
}

func (i *InMemoryStorageEngine) LookupVRFRotationProof(ctx logger.ContextInterface, t Transaction, p Period) (vrf.RotationProof, error) {
	return i.VRFRotationProofs[p], nil
}

func (i *InMemoryStorageEngine) LookupVRFPrivateKey(ctx logger.ContextInterface, t Transaction, p Period) (*vrf.PrivateKey, error) {
	sk, ok := i.VRFPrivateKeys[p]
	if !ok {
		return nil, fmt.Errorf("no private key for period %d", p)
	}
	return sk, nil
}

func (s *InMemoryStorageEngine) ArraySet(ctx logger.ContextInterface, t Transaction, i int, x []byte) error {
	s.ArrayDat[i] = x
	return nil
}

func (s *InMemoryStorageEngine) ArrayGet(ctx logger.ContextInterface, t Transaction, i int) ([]byte, error) {
	x, ok := s.ArrayDat[i]
	if ok {
		return x, nil
	}
	return nil, fmt.Errorf("out of bounds")
}

func (s *InMemoryStorageEngine) ArrayGets(ctx logger.ContextInterface, t Transaction, is []int) ([][]byte, error) {
	var ret [][]byte
	for _, i := range is {
		x, ok := s.ArrayDat[i]
		if !ok {
			return nil, fmt.Errorf("out of bounds")
		}
		ret = append(ret, x)
	}
	return ret, nil
}

func (s *InMemoryStorageEngine) ArrayLen(ctx logger.ContextInterface, t Transaction) (int, error) {
	return len(s.ArrayDat), nil
}

func (s *InMemoryStorageEngine) LookupPlayers(ctx logger.ContextInterface, t Transaction, id [][]byte) ([][]byte, error) {
	return nil, nil
}

func (s *InMemoryStorageEngine) StorePlayers(ctx logger.ContextInterface, t Transaction, id [][]byte, pl [][]byte) error {
	return nil
}
