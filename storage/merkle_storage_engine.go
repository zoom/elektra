package storage

import (
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"sort"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/jmoiron/sqlx"
	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/merkle"
	"github.com/mvkdcrypto/mvkd/demo/vrf"
	"github.com/pkg/errors"

	sq "github.com/Masterminds/squirrel"
)

// MerkleStorageEngine implements the merkle.StorageEngineWithBlinding
// interface. It is a thin wrapper around mysql and does not perform any
// batching or caching.

var CachePollardMaxLevel = 29

type Nodeseqno struct {
	Hash  []byte
	Seqno merkle.Seqno
}
type MerkleStorageEngine struct {
	db           *sqlx.DB
	leveldb      *leveldb.DB
	nodeCache    *sync.Map // only stores latest version
	iteratorPool *sync.Pool

	cfg    merkle.Config
	treeId []byte

	TotalLookupNodes     int
	TotalShortcircuits   int
	TotalCacheHits       int
	TotalCacheMiss       int
	TotalCacheNonpollard int
	TotalEvictions       int
	MaxDepth             int
	TotalDepth           int
	TotalLooks           int
}

var _ merkle.StorageEngine = &MerkleStorageEngine{}

func NewMerkleStorageEngine(db *sqlx.DB, cfg merkle.Config, treeId []byte) *MerkleStorageEngine {
	if cfg.MaxValuesPerLeaf != 1 {
		panic(fmt.Sprintf("This engine only supports binary trees with a single value per leaf, but got %d", cfg.MaxValuesPerLeaf))
	}

	name := hex.EncodeToString(treeId)
	opts := opt.Options{
		// BlockCacheCapacity:            768 / 2 * opt.MiB,
		// CompactionTableSize:           100 * opt.MiB,
		// WriteBuffer: (768 / 4) * opt.MiB,
		// CompactionL0Trigger:           16,
		// Filter: filter.NewBloomFilter(10),
		// CompactionTotalSize:           500 * opt.MiB,
		// CompactionTotalSizeMultiplier: 15,
	}
	leveldb, err := leveldb.OpenFile("db/lev"+name, &opts)
	if err != nil {
		panic(err)
	}

	return &MerkleStorageEngine{
		db:        db,
		leveldb:   leveldb,
		cfg:       cfg,
		treeId:    treeId,
		nodeCache: new(sync.Map),
	}
}

func (m *MerkleStorageEngine) Tx() *sqlx.Tx {
	return m.db.MustBegin()
}

func (m *MerkleStorageEngine) Reset() error {
	tx := m.db.MustBegin()
	tx.MustExec(`DROP TABLE IF EXISTS vrf_cache`)
	tx.MustExec(`CREATE TABLE vrf_cache(
		tree_id bytea,
		period bigint,
		key bytea,
		hidden_key bytea,
		vrf_proof bytea,
		PRIMARY KEY (tree_id, period, key)
	);`)
	tx.MustExec(`DROP TABLE IF EXISTS pairs`)
	tx.MustExec(`CREATE TABLE pairs(
		tree_id bytea,
		period bigint,
		hidden_key bytea,
		seqno bigint,
		key bytea,
		added_at_seqno bigint,
		encoded_value bytea,
		entropy bytea,
		PRIMARY KEY (tree_id, period, hidden_key, seqno)
	);`)
	tx.MustExec(`DROP TABLE IF EXISTS roots`)
	tx.MustExec(`CREATE TABLE roots(
		tree_id bytea,
		seqno bigint,
		root_metadata bytea,
		PRIMARY KEY (tree_id, seqno)
	);`)
	tx.MustExec(`DROP TABLE IF EXISTS vrf_rotation_proofs`)
	tx.MustExec(`CREATE TABLE vrf_rotation_proofs(
		tree_id bytea,
		period bigint,
		proof bytea,
		PRIMARY KEY (tree_id, period)
	);`)
	tx.MustExec(`DROP TABLE IF EXISTS vrf_private_keys`)
	tx.MustExec(`CREATE TABLE vrf_private_keys(
		tree_id bytea,
		period bigint,
		private_key bytea,
		PRIMARY KEY (tree_id, period)
	);`)
	tx.MustExec(`DROP TABLE IF EXISTS history_tree_nodes`)
	tx.MustExec(`CREATE TABLE history_tree_nodes(
		tree_id bytea,
		idx bigint,
		value bytea,
		PRIMARY KEY (tree_id, idx)
	);`)
	tx.MustExec(`DROP TABLE IF EXISTS sigchain_player_cache`)
	tx.MustExec(`CREATE TABLE sigchain_player_cache(
		tree_id bytea,
		user_id bytea,
		value bytea,
		PRIMARY KEY (tree_id, user_id)
	);`)
	tx.Commit()

	return nil
}

func (m *MerkleStorageEngine) StoreVRFCache(ctx logger.ContextInterface, tr merkle.Transaction,
	per merkle.Period, ks []merkle.Key, hks []merkle.HiddenKey, vrfProofs [][]byte) error {
	if len(ks) == 0 {
		return nil
	}

	// tx := m.Tx()
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return errors.New("Require sqlx tx")
	}

	for i := 0; i < len(ks); i += 10000 {
		lim := 10000
		if len(ks)-i < 10000 {
			lim = len(ks)
		}
		subks := ks[i : i+lim]
		subhks := hks[i : i+lim]
		subproofs := vrfProofs[i : i+lim]

		builder := sq.
			Insert("vrf_cache").
			Columns("tree_id", "period", "key", "hidden_key", "vrf_proof")
		for j, k := range subks {
			hk := subhks[j]
			vrfProof := subproofs[j]
			builder = builder.Values(m.treeId, per, k, hk, vrfProof)
		}
		builder = builder.Suffix("on conflict (tree_id, period, key) do nothing")

		q, args, err := builder.ToSql()
		if err != nil {
			return errors.Wrap(err, "msg")
		}
		q = m.db.Rebind(q)
		_, err = tx.Exec(q, args...)
		if err != nil {
			// tx.Rollback()
			return errors.Wrap(err, "msg")
		}
	}

	// err := tx.Commit()
	// if err != nil {
	// 	return errors.Wrap(err, "msg")
	// }

	return nil
}

type VRFEntry struct {
	HiddenKey merkle.HiddenKey `db:"hidden_key"`
	VRFProof  []byte           `db:"vrf_proof"`
}

func (m *MerkleStorageEngine) LookupVRFCache(ctx logger.ContextInterface, tr merkle.Transaction,
	per merkle.Period, k merkle.Key) (merkle.HiddenKey, []byte, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return nil, nil, errors.New("Require sqlx tx")
	}

	var ret VRFEntry
	q := `SELECT hidden_key, vrf_proof FROM vrf_cache WHERE tree_id=? AND period=? AND key=?`
	q = m.db.Rebind(q)
	err := tx.Get(&ret, q, m.treeId, per, k)
	switch err {
	case nil:
		return ret.HiddenKey, ret.VRFProof, nil
	case sql.ErrNoRows:
		return nil, nil, nil
	default:
		return nil, nil, errors.Wrap(err, "msg")
	}
}

func (m *MerkleStorageEngine) StorePairs(ctx logger.ContextInterface, tr merkle.Transaction,
	s merkle.Seqno, per merkle.Period, hkvps []merkle.HiddenKeyValuePair) error {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return errors.New("Require sqlx tx")
	}

	if len(hkvps) == 1 {
		q := `INSERT into pairs(tree_id,seqno,period,hidden_key,key,added_at_seqno,encoded_value,entropy) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`
		pair := hkvps[0]
		q = m.db.Rebind(q)
		_, err := tx.Exec(q,
			m.treeId, s, per, pair.HiddenKey, pair.Key, pair.AddedAtSeqno, pair.EncodedValue, pair.Entropy)
		if err != nil {
			return errors.Wrap(err, "msg")
		}
		return nil
	}

	builder := sq.
		Insert("pairs").
		Columns("tree_id", "seqno", "period", "hidden_key", "key", "added_at_seqno", "encoded_value", "entropy")
	for _, hkvp := range hkvps {
		builder = builder.Values(m.treeId, s, per,
			hkvp.HiddenKey, hkvp.Key, hkvp.AddedAtSeqno, hkvp.EncodedValue, hkvp.Entropy)
	}

	q, args, err := builder.ToSql()
	if err != nil {
		return errors.Wrap(err, "msg")
	}

	q = m.db.Rebind(q)
	_, err = tx.Exec(q, args...)
	if err != nil {
		return errors.Wrap(err, "msg")
	}

	return nil
}

func (m *MerkleStorageEngine) LookupPair(ctx logger.ContextInterface, tr merkle.Transaction,
	per merkle.Period, s merkle.Seqno, k merkle.HiddenKey) (merkle.HiddenKeyValuePair, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return merkle.HiddenKeyValuePair{}, errors.New("Require sqlx tx")
	}

	var pair merkle.HiddenKeyValuePair
	q := `SELECT hidden_key, key, added_at_seqno, encoded_value, entropy
		FROM pairs WHERE tree_id=? AND period=? AND hidden_key=? AND seqno<=?`
	// Don't need to limit 1 because there should be at most one anyway
	q = m.db.Rebind(q)
	err := tx.Get(&pair, q, m.treeId, per, k, s)
	switch err {
	case nil:
	case sql.ErrNoRows:
		return merkle.HiddenKeyValuePair{}, merkle.NewKeyNotFoundError()
	default:
		return merkle.HiddenKeyValuePair{}, errors.Wrap(err, "msg")
	}

	return pair, nil
}

func (m *MerkleStorageEngine) LookupPairsUnderPosition(ctx logger.ContextInterface, tr merkle.Transaction,
	s merkle.Seqno, per merkle.Period, p *merkle.Position) (hkvps []merkle.HiddenKeyValuePair, err error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return nil, errors.New("Require sqlx tx")
	}

	minKey, maxKey := m.cfg.GetKeyIntervalUnderPosition(p)

	pairs := make([]merkle.HiddenKeyValuePair, 0, 2)

	q := `SELECT hidden_key, key, added_at_seqno, encoded_value, entropy
		FROM pairs
		WHERE tree_id=$1 AND period=$2
		AND hidden_key BETWEEN $3 and $4
		AND seqno<=$5
		ORDER BY hidden_key`
	rows, err := tx.Query(q, m.treeId, per, minKey, maxKey, s)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		pair := merkle.HiddenKeyValuePair{}
		err := rows.Scan(&pair.HiddenKey, &pair.Key, &pair.AddedAtSeqno, &pair.EncodedValue, &pair.Entropy)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, pair)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	if len(pairs) == 0 {
		return nil, merkle.NewKeyNotFoundError()
	}

	return pairs, nil
}

func (m *MerkleStorageEngine) LookupAllPairs(ctx logger.ContextInterface, tr merkle.Transaction,
	s merkle.Seqno, per merkle.Period) ([]merkle.HiddenKeyValuePair, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return nil, errors.New("Require sqlx tx")
	}

	var pairs []merkle.HiddenKeyValuePair
	q := `SELECT hidden_key, key, added_at_seqno, encoded_value, entropy
		FROM pairs
		WHERE tree_id=? AND period=?
		AND seqno<=?`
	q = m.db.Rebind(q)
	err := tx.Select(&pairs, q,
		m.treeId, per, s)
	if err != nil {
		return nil, errors.Wrap(err, "msg")
	}

	// TODO: We could batch this in 1/16ths to not lock up db for too long
	// but then again maybe it's only read lock...
	return pairs, nil
}

func (m *MerkleStorageEngine) keyPrefix(per merkle.Period, p *merkle.Position) []byte {
	var b []byte

	periodB := make([]byte, 8)
	binary.BigEndian.PutUint64(periodB, uint64(per))
	b = append(b, periodB...)

	pbytes := make([]byte, 33)
	((*big.Int)(p)).FillBytes(pbytes)
	b = append(b, pbytes...)

	return b
}

func (m *MerkleStorageEngine) calcKey(per merkle.Period, p *merkle.Position, s merkle.Seqno) []byte {
	b := make([]byte, 49)
	binary.BigEndian.PutUint64(b[0:8], uint64(per))
	((*big.Int)(p)).FillBytes(b[8:41])
	binary.BigEndian.PutUint64(b[41:49], uint64(s))

	return b
}

func (m *MerkleStorageEngine) StoreNodes(ctx logger.ContextInterface, tr merkle.Transaction, s merkle.Seqno,
	per merkle.Period, phpairs []merkle.PositionHashPair) error {

	batch := new(leveldb.Batch)
	for _, phpair := range phpairs {
		k := m.calcKey(per, &phpair.Position, s)
		v := phpair.Hash
		batch.Put(k, v)
		if m.cfg.GetLevel(&phpair.Position) <= CachePollardMaxLevel {
			evicted := m.getNodeCache(per).Add(phpair.Position.AsString(), phpair.Hash)
			if evicted {
				m.TotalEvictions += 1
			}
		}
	}

	err := m.leveldb.Write(batch, nil)
	if err != nil {
		return errors.Wrap(err, "msg")
	}
	return nil
}

func (m *MerkleStorageEngine) LookupNode(c logger.ContextInterface, tr merkle.Transaction, s merkle.Seqno, per merkle.Period, p *merkle.Position) ([]byte, error) {
	return m.lookupNode(s, per, p, false)
}

func (m *MerkleStorageEngine) LookupNodes(c logger.ContextInterface, tr merkle.Transaction,
	s merkle.Seqno, per merkle.Period, positions []*merkle.Position, includeNils bool, latest bool) ([]merkle.PositionHashPair, error) {
	if latest {
		m.TotalDepth += len(positions) / 2
		m.TotalLooks += 1
	}
	ret := make([]merkle.PositionHashPair, 0, len(positions))
	maxDepth := -1
	for i, pos := range positions {
		depth := 0
		if i == 0 {
			depth = 0
		} else {
			depth = (i + 1) / 2
		}
		if latest && maxDepth != -1 && depth > maxDepth {
			m.TotalShortcircuits += 1
			if includeNils {
				ret = append(ret, merkle.PositionHashPair{Position: *pos, Hash: nil})
			}
			continue
		}
		hash, err := m.lookupNode(s, per, pos, latest)
		switch err.(type) {
		case nil:
			ret = append(ret, merkle.PositionHashPair{Position: *pos, Hash: hash})
		case merkle.NodeNotFoundError:
			if includeNils {
				ret = append(ret, merkle.PositionHashPair{Position: *pos, Hash: nil})
			}
			if i == 0 || i%2 == 1 {
				maxDepth = depth
			}
		default:
			return nil, err
		}
	}

	if maxDepth > m.MaxDepth {
		m.MaxDepth = maxDepth
	}
	return ret, nil
}

func (m *MerkleStorageEngine) getNodeCache(per merkle.Period) *lru.Cache[string, []byte] {
	cache, ok := m.nodeCache.Load(per)
	if ok {
		return cache.(*lru.Cache[string, []byte])
	}
	cache, err := lru.New[string, []byte](250000000)
	if err != nil {
		panic(err.Error())
	}
	_, loaded := m.nodeCache.LoadAndDelete(per - 1)
	if loaded {
		runtime.GC()
	}
	m.nodeCache.Store(per, cache)

	return cache.(*lru.Cache[string, []byte])
}

func (m *MerkleStorageEngine) lookupNode(s merkle.Seqno, per merkle.Period, p *merkle.Position, latest bool) ([]byte, error) {
	m.TotalLookupNodes += 1
	var iter iterator.Iterator
	if latest {
		if m.cfg.GetLevel(p) <= CachePollardMaxLevel {
			v, cacheOk := m.getNodeCache(per).Get(p.AsString())
			if cacheOk {
				m.TotalCacheHits += 1
				if v == nil {
					return nil, merkle.NewNodeNotFoundError()
				} else {
					return v, nil
				}
			} else {
				m.TotalCacheMiss += 1
			}
		} else {
			m.TotalCacheNonpollard += 1
		}
		iter = m.leveldb.NewIterator(util.BytesPrefix(m.keyPrefix(per, p)), nil)
	} else {
		start := m.calcKey(per, p, 0)
		limit := m.calcKey(per, p, s+1)
		iter = m.leveldb.NewIterator(&util.Range{Start: start, Limit: limit}, nil)
	}
	ok := iter.Last()
	var val []byte
	if ok {
		val = iter.Value()
	}
	iter.Release()
	err := iter.Error()
	if err != nil {
		return nil, err
	}

	if !ok {
		if latest && m.cfg.GetLevel(p) <= CachePollardMaxLevel {
			s := p.AsString()
			evicted := m.getNodeCache(per).Add(s, nil)
			if evicted {
				m.TotalEvictions += 1
			}
		}
		return nil, merkle.NewNodeNotFoundError()
	}

	return val, nil
}

// StoreRoot(ctx logger.ContextInterface, tr Transaction, md RootMetadata) error
func (m *MerkleStorageEngine) StoreRoot(ctx logger.ContextInterface, tr merkle.Transaction,
	md merkle.RootMetadata) error {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return errors.New("Require sqlx tx")
	}

	encodedMd, err := m.cfg.Encoder.Encode(md)
	if err != nil {
		return errors.Wrap(err, "cannot encode root metadata")
	}

	builder := sq.
		Insert("roots").
		Columns("tree_id", "seqno", "root_metadata").
		Values(m.treeId, md.Seqno, encodedMd)

	q, args, err := builder.ToSql()
	if err != nil {
		return err
	}

	q = m.db.Rebind(q)
	_, err = tx.Exec(q, args...)
	if err != nil {
		return errors.Wrap(err, "msg")
	}

	return nil
}

type NodeResult struct {
	Position merkle.Position `db:"position"`
	Hash     []byte          `db:"hash"`
	Seqno    merkle.Seqno    `db:"seqno"`
}

func findHash(ret []Nodeseqno, s merkle.Seqno) []byte {
	if len(ret) == 0 {
		return nil
	}

	i := sort.Search(len(ret), func(i int) bool {
		return ret[i].Seqno > s
	})
	if i == 0 {
		return nil
	}
	return ret[i-1].Hash
}

func (m *MerkleStorageEngine) LookupLatestRoot(ctx logger.ContextInterface, tr merkle.Transaction) (merkle.RootMetadata, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return merkle.RootMetadata{}, errors.New("Require sqlx tx")

	}

	var rootMdBytes []byte
	// might have to encode into bytes first... here and in storenode
	q := `SELECT root_metadata
		FROM roots
		WHERE tree_id=?
		ORDER BY seqno DESC
		LIMIT 1`
	q = m.db.Rebind(q)
	err := tx.Get(&rootMdBytes, q, m.treeId)
	switch err {
	case nil:
	case sql.ErrNoRows:
		return merkle.RootMetadata{}, merkle.NewNoLatestRootFoundError()
	default:
		return merkle.RootMetadata{}, errors.Wrap(err, "msg")
	}

	var rootMd merkle.RootMetadata
	err = m.cfg.Encoder.Decode(&rootMd, rootMdBytes)
	if err != nil {
		return merkle.RootMetadata{}, err
	}

	return rootMd, nil
}

func (m *MerkleStorageEngine) LookupRoot(ctx logger.ContextInterface, tr merkle.Transaction, s merkle.Seqno) (merkle.RootMetadata, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return merkle.RootMetadata{}, errors.New("Require sqlx tx")

	}

	var rootMdBytes []byte
	// might have to encode into bytes first... here and in storenode
	q := `SELECT root_metadata
		FROM roots
		WHERE tree_id=?
		AND seqno=?
		LIMIT 1`
	q = m.db.Rebind(q)
	err := tx.Get(&rootMdBytes, q,
		m.treeId, s)
	if err != nil {
		return merkle.RootMetadata{}, errors.Wrap(err, "msg")
	}

	var rootMd merkle.RootMetadata
	err = m.cfg.Encoder.Decode(&rootMd, rootMdBytes)
	if err != nil {
		return merkle.RootMetadata{}, err
	}

	return rootMd, nil
}

func (m *MerkleStorageEngine) StoreVRFRotationProof(ctx logger.ContextInterface, tr merkle.Transaction,
	per merkle.Period, pi vrf.RotationProof) error {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return errors.New("Require sqlx tx")
	}

	proofBytes, err := m.cfg.Encoder.Encode(pi)
	if err != nil {
		return errors.Wrap(err, "cannot encode root metadata")
	}

	builder := sq.
		Insert("vrf_rotation_proofs").
		Columns("tree_id", "period", "proof").
		Values(m.treeId, per, proofBytes)

	q, args, err := builder.ToSql()
	if err != nil {
		return err
	}

	q = m.db.Rebind(q)
	_, err = tx.Exec(q, args...)
	if err != nil {
		return errors.Wrap(err, "msg")
	}

	return nil
}

func (m *MerkleStorageEngine) LookupVRFRotationProof(ctx logger.ContextInterface,
	tr merkle.Transaction, per merkle.Period) (vrf.RotationProof, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return vrf.RotationProof{}, errors.New("Require sqlx tx")

	}

	var proofBytes []byte
	q := `SELECT proof
		FROM vrf_rotation_proofs
		WHERE tree_id=?
		AND period=?
		LIMIT 1`
	q = m.db.Rebind(q)
	err := tx.Get(&proofBytes, q,
		m.treeId, per)
	if err != nil {
		return vrf.RotationProof{}, errors.Wrap(err, "msg")
	}

	var proof vrf.RotationProof
	err = m.cfg.Encoder.Decode(&proof, proofBytes)
	if err != nil {
		return vrf.RotationProof{}, err
	}

	return proof, nil
}

// Outsourced to secure storage in practice
func (m *MerkleStorageEngine) StoreVRFPrivateKey(ctx logger.ContextInterface, tr merkle.Transaction,
	per merkle.Period, sk *vrf.PrivateKey) error {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return errors.New("Require sqlx tx")
	}

	skBytes := sk.Bytes()
	builder := sq.
		Insert("vrf_private_keys").
		Columns("tree_id", "period", "private_key").
		Values(m.treeId, per, skBytes)

	q, args, err := builder.ToSql()
	if err != nil {
		return err
	}

	q = m.db.Rebind(q)
	_, err = tx.Exec(q, args...)
	if err != nil {
		return errors.Wrap(err, "msg")
	}

	return nil
}

// Outsourced to secure storage in practice
func (m *MerkleStorageEngine) LookupVRFPrivateKey(ctx logger.ContextInterface, tr merkle.Transaction, per merkle.Period) (*vrf.PrivateKey, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return nil, errors.New("Require sqlx tx")
	}

	var vrfSkBytes []byte
	q := `SELECT private_key
		FROM vrf_private_keys
		WHERE tree_id=?
		AND period=?
		LIMIT 1`
	q = m.db.Rebind(q)

	err := tx.Get(&vrfSkBytes, q, m.treeId, per)
	if err != nil {
		return nil, errors.Wrap(err, "msg")
	}
	return vrf.NewKey(m.cfg.ECVRF.Params().EC(), vrfSkBytes), nil
}

func (m *MerkleStorageEngine) ArraySet(ctx logger.ContextInterface, tr merkle.Transaction, i int, x []byte) error {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return errors.New("Require sqlx tx")
	}

	builder := sq.
		Insert("history_tree_nodes").
		Columns("tree_id", "idx", "value").
		Suffix("on conflict (tree_id, idx) do update set value=excluded.value")

	builder = builder.Values(m.treeId, i, x)

	q, args, err := builder.ToSql()
	if err != nil {
		return err
	}

	q = m.db.Rebind(q)
	_, err = tx.Exec(q, args...)
	if err != nil {
		return errors.Wrap(err, "msg")
	}

	return nil
}

func (m *MerkleStorageEngine) ArrayGet(ctx logger.ContextInterface, tr merkle.Transaction,
	i int) ([]byte, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return nil, errors.New("Require sqlx tx")
	}

	var value []byte
	q := `SELECT value FROM history_tree_nodes WHERE tree_id=? AND idx=?`
	q = m.db.Rebind(q)
	err := tx.Get(&value, q, m.treeId, i)
	if err != nil {
		return nil, errors.Wrap(err, "msg")
	}

	return value, nil
}

type V struct {
	Idx   int    `db:"idx"`
	Value []byte `db:"value"`
}

func (m *MerkleStorageEngine) ArrayGets(ctx logger.ContextInterface, tr merkle.Transaction,
	is []int) ([][]byte, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return nil, errors.New("Require sqlx tx")
	}

	if len(is) == 0 {
		return nil, nil
	}

	var vs []V
	query, args, err := sqlx.In(`SELECT idx, value
	FROM history_tree_nodes WHERE tree_id=? AND idx IN (?)`, m.treeId, is)
	if err != nil {
		return nil, errors.Wrap(err, "msg")
	}
	query = m.db.Rebind(query)
	err = tx.Select(&vs, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "msg")
	}

	lookup := make(map[int][]byte)
	for _, v := range vs {
		lookup[v.Idx] = v.Value
	}

	var ret [][]byte
	for _, i := range is {
		ret = append(ret, lookup[i])
	}

	return ret, nil
}

func (m *MerkleStorageEngine) ArrayLen(ctx logger.ContextInterface, tr merkle.Transaction) (int, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return 0, errors.New("Require sqlx tx")
	}

	var count int
	q := `SELECT COUNT(*) as c FROM history_tree_nodes WHERE tree_id=?`
	q = m.db.Rebind(q)
	err := tx.Get(&count, q,
		m.treeId)
	if err != nil {
		return 0, errors.Wrap(err, "msg")
	}

	return count, nil
}

func (m *MerkleStorageEngine) LookupPlayers(ctx logger.ContextInterface, tr merkle.Transaction, ids [][]byte) ([][]byte, error) {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return nil, errors.New("Require sqlx tx")
	}

	type st struct {
		UserId []byte `db:"user_id"`
		Value  []byte `db:"value"`
	}

	if len(ids) == 0 {
		return nil, nil
	}

	var values []st
	q := `SELECT user_id, value FROM sigchain_player_cache WHERE tree_id=? AND user_id IN (?)`
	query, args, err := sqlx.In(q, m.treeId, ids)
	if err != nil {
		return nil, err
	}
	query = m.db.Rebind(query)
	err = tx.Select(&values, query, args...)
	if err != nil {
		return nil, err
	}

	lookup := make(map[string]st)
	for _, value := range values {
		lookup[hex.EncodeToString(value.UserId)] = value
	}

	ret := make([][]byte, len(ids))
	for i, id := range ids {
		v, ok := lookup[hex.EncodeToString(id)]
		if ok {
			ret[i] = v.Value
		}
	}

	return ret, nil
}

func (m *MerkleStorageEngine) StorePlayers(ctx logger.ContextInterface, tr merkle.Transaction, ids [][]byte, pls [][]byte) error {
	tx, ok := tr.(*sqlx.Tx)
	if !ok {
		return errors.New("Require sqlx tx")
	}

	if len(ids) == 0 {
		return nil
	}

	builder := sq.
		Insert("sigchain_player_cache").
		Columns("tree_id", "user_id", "value").
		Suffix("on conflict (tree_id, user_id) do update set value=excluded.value")
	for i, _ := range ids {
		builder = builder.Values(m.treeId, ids[i], pls[i])
	}

	q, args, err := builder.ToSql()
	if err != nil {
		return err
	}

	q = m.db.Rebind(q)
	_, err = tx.Exec(q, args...)
	if err != nil {
		return errors.Wrap(err, "msg")
	}

	return nil
}
