package merkle

import (
	"crypto/sha256"
	"fmt"

	"github.com/mvkdcrypto/mvkd/demo/logger"
)

// We store an LBBT Merkle tree as an array
// Leaves are even integers starting with zero
// lbbt math from https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-secret-tree

type ArrayStorage interface {
	ArraySet(ctx logger.ContextInterface, tr Transaction, i int, x []byte) error
	ArrayGet(ctx logger.ContextInterface, tr Transaction, i int) ([]byte, error)
	ArrayGets(ctx logger.ContextInterface, tr Transaction, is []int) ([][]byte, error)
	ArrayLen(ctx logger.ContextInterface, tr Transaction) (int, error)
}

type LBBMT struct {
	storage ArrayStorage
}

func NewLBBMT(storage ArrayStorage) *LBBMT {
	return &LBBMT{storage}
}

func (l *LBBMT) Root(ctx logger.ContextInterface, tr Transaction) ([]byte, error) {
	N, err := l.size(ctx, tr)
	if err != nil {
		return nil, err
	}
	if N == 0 {
		return nil, fmt.Errorf("empty lbbmt")
	}
	return l.storage.ArrayGet(ctx, tr, root(N))
}

type LBBMTNode struct {
	left  []byte
	right []byte
}

// use ctx string in practice
func (n *LBBMTNode) hash() []byte {
	//return append(n.left, n.right...)

	h := sha256.New()
	h.Write(n.left)
	h.Write(n.right)
	return []byte(h.Sum(nil))
}

func (l *LBBMT) size(ctx logger.ContextInterface, tr Transaction) (int, error) {
	n, err := l.storage.ArrayLen(ctx, tr)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return (n / 2) + 1, nil
}

func (l *LBBMT) Gets(ctx logger.ContextInterface, tr Transaction, is []int) ([][]byte, error) {
	return l.storage.ArrayGets(ctx, tr, is)
}

// For every new leaf, we add two nodes: the leaf, and the parent of that leaf.
// We also update existing nodes going up to the root.
func (l *LBBMT) Push(ctx logger.ContextInterface, tr Transaction, val []byte) error {
	oldN, err := l.size(ctx, tr)
	if err != nil {
		return err
	}

	err = l.storage.ArraySet(ctx, tr, oldN*2, val)
	if err != nil {
		return err
	}

	if oldN == 0 {
		return nil
	}

	N, err := l.size(ctx, tr)
	if err != nil {
		return err
	}
	x := parent(2*(N-1), N) // just x - 1?
	r := root(N)

	for {
		lt, err := l.storage.ArrayGet(ctx, tr, left(x))
		if err != nil {
			return err
		}
		rt, err := l.storage.ArrayGet(ctx, tr, right(x, N))
		if err != nil {
			return err
		}
		h := lbbmtHash(lt, rt)
		err = l.storage.ArraySet(ctx, tr, x, h)
		if err != nil {
			return err
		}

		if x == r {
			break
		}

		x = parent(x, N)
	}

	return nil
}

func lbbmtHash(left, right []byte) []byte {
	n := LBBMTNode{left: left, right: right}
	return n.hash()
}

func left(x int) int {
	k := level(x)
	if k == 0 {
		panic("leaf node has no children")
	}
	return x ^ (0x01 << (k - 1))
}

func right(x int, n int) int {
	k := level(x)
	if k == 0 {
		panic("leaf node has no children")
	}
	r := x ^ (0x03 << (k - 1))
	for r >= nodeWidth(n) {
		r = left(r)
	}
	return r
}

// We need to know how many nodes. for example,
// node 8 is a left child with 5 leaves, and a right child with 6 leaves.
func isLeftChild(x int, n int) bool {
	return x == left(parent(x, n))
}

// floor(log2(x))
func log2(x int) int {
	if x == 0 {
		return 0
	}
	k := 0
	for (x >> k) > 0 {
		k += 1
	}
	return k - 1
}

func root(n int) int {
	w := nodeWidth(n)
	return (1 << log2(w)) - 1
}

func level(x int) int {
	if x&0x01 == 0 {
		return 0
	}
	k := 0
	for ((x >> k) & 0x01) == 1 {
		k += 1
	}
	return k
}

func parentStep(x int) int {
	k := level(x)
	b := (x >> (k + 1)) & 0x01
	return (x | (1 << k)) ^ (b << (k + 1))
}

func nodeWidth(n int) int {
	if n == 0 {
		return 0
	} else {
		return 2*(n-1) + 1
	}
}

func parent(x int, n int) int {
	if x == root(n) {
		panic("root node has no parent")
	}
	p := parentStep(x)
	for p >= nodeWidth(n) {
		p = parentStep(p)
	}
	return p
}

func auditProofIndices(from Seqno, to Seqno) []int {
	return auditProofIndicesHelper(int(to)*2-1, int(from)*2-2)
}

// n is number of nodes
func auditProofIndicesHelper(n int, idx int) []int {
	if n == 1 {
		return []int{}
	}
	p := pivot(n)
	if idx < (p - 1) {
		return append(auditProofIndicesHelper(p-1, idx), p-1+pivot(n-p))
	}
	rec := auditProofIndicesHelper(n-p, idx-p)
	for i, r := range rec {
		rec[i] = r + p
	}
	return append(rec, pivot(p-1)-1)
}

// We assume the user already has the roots for the bounds and so we don't include them
func consistencyProofIndices(fromSeqno Seqno, toSeqno Seqno) []int {
	return consistencyProofHelper(int(toSeqno)*2-1, int(fromSeqno)*2-2, true)
}

func pivot(n int) int {
	i := 0
	for n > 0 {
		n >>= 1
		i += 1
	}
	return 1 << (i - 1)
}

// n is # of nodes
func consistencyProofHelper(n int, idx int, init bool) []int {
	if idx == n-1 {
		if init {
			return []int{}
		} else {
			return []int{pivot(n) - 1}
		}
	}
	p := pivot(n)
	if idx < (p - 1) {
		rec := consistencyProofHelper(p-1, idx, init)
		return append(rec, p-1+pivot(n-p))
	}
	rec := consistencyProofHelper(n-p, idx-p, false)
	for idx, x := range rec {
		rec[idx] = x + p
	}
	return append(rec, pivot(p-1)-1)
}
