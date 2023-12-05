package merkle

import (
	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/vrf"
)

// StorageEngine specifies how to store and lookup merkle tree nodes, roots and
// KeyEncodedValuePairs. You can use a DB like Dynamo or SQL to do this.
type StorageEngine interface {
	ArrayStorage

	// StorePairs stores the []HiddenKeyValuePair in the tree.
	StorePairs(logger.ContextInterface, Transaction, Seqno, Period, []HiddenKeyValuePair) error

	// StoreNode takes multiple pairs of a position and a hash, and stores each
	// hash (of a tree node) at the corresponding position and at the supplied
	// Seqno in the tree.
	StoreNodes(logger.ContextInterface, Transaction, Seqno, Period, []PositionHashPair) error

	// StoreRootMetadata stores the supplied RootMetadata, along with the
	// corresponding Hash.
	StoreRoot(ctx logger.ContextInterface, tr Transaction, md RootMetadata) error

	// LookupLatestRoot returns the latest root metadata and sequence number in
	// the tree. If no root is found, then a NoLatestRootFound error is returned.
	LookupLatestRoot(logger.ContextInterface, Transaction) (RootMetadata, error)

	// If there is no root for the specified Seqno, an InvalidSeqnoError is returned.
	LookupRoot(logger.ContextInterface, Transaction, Seqno) (RootMetadata, error)

	// LookupNode returns, for any position, the hash of the node with the
	// highest Seqno s' <= s which was stored at position p. For example, if
	// StoreNode(ctx, t, 5, p, hash5) and StoreNode(ctx, 6, p, hash6) and
	// StoreNode(ctx, t, 8, p, hash8) were called for a specific position p,
	// then LookupNode(ctx, t, 7, p) would return hash6. It returns an error if
	// no such node was stored in the tree.
	LookupNode(c logger.ContextInterface, t Transaction, s Seqno, per Period, p *Position) ([]byte, error)

	// LookupNodes is analogous to LookupNode, but it takes more than one
	// position and returns pairs of a Position and the corresponding node Hash
	// only for the nodes which are found in the tree. No error is returned if
	// some of the positions are not found.
	// LookupNodesPlace(c logger.ContextInterface, t Transaction, s Seqno, per Period, positions []Position, includeNils bool, ret []PositionHashPair) error
	// if s==-1, looks up the latest version
	LookupNodes(c logger.ContextInterface, t Transaction, s Seqno, per Period, positions []*Position, includeNils bool, latest bool) ([]PositionHashPair, error)

	StoreVRFCache(c logger.ContextInterface, t Transaction, per Period, k []Key, hk []HiddenKey, vrf_proof [][]byte) error
	LookupVRFCache(c logger.ContextInterface, t Transaction, per Period, k Key) (HiddenKey, []byte, error)

	LookupPair(c logger.ContextInterface, t Transaction, per Period, s Seqno, k HiddenKey) (HiddenKeyValuePair, error)

	// LookupPairsUnderPosition returns all HiddenKeyValuePairs (ordered by
	// Key) which were stored at a position p' which is a descendent of p and at
	// the maximum Seqno s' <= s (similarly to LookupNode). For each such pair,
	// it returns the Seqno at which it was stored (in the same order).
	LookupPairsUnderPosition(ctx logger.ContextInterface, t Transaction, s Seqno, per Period, p *Position) ([]HiddenKeyValuePair, error)

	// LookupAllPairs returns all the keys and encoded values at the specified Seqno.
	LookupAllPairs(ctx logger.ContextInterface, t Transaction, s Seqno, per Period) ([]HiddenKeyValuePair, error)

	// May be too large to fit in standard database column
	StoreVRFRotationProof(ctx logger.ContextInterface, t Transaction, p Period, pi vrf.RotationProof) error

	// nil for p=1
	LookupVRFRotationProof(ctx logger.ContextInterface, t Transaction, p Period) (vrf.RotationProof, error)

	// Outsourced to secure storage in practice
	StoreVRFPrivateKey(ctx logger.ContextInterface, t Transaction, p Period, sk *vrf.PrivateKey) error

	// Outsourced to secure storage in practice
	LookupVRFPrivateKey(ctx logger.ContextInterface, t Transaction, p Period) (*vrf.PrivateKey, error)

	LookupPlayers(ctx logger.ContextInterface, t Transaction, id [][]byte) ([][]byte, error)
	StorePlayers(ctx logger.ContextInterface, t Transaction, id [][]byte, player [][]byte) error
}

// Transaction references a DB transaction.
type Transaction interface{}
