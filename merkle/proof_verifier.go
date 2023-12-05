package merkle

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"math/big"

	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/vrf"
)

type MerkleProofVerifier struct {
	cfg Config
}

func NewMerkleProofVerifier(c Config) MerkleProofVerifier {
	return MerkleProofVerifier{cfg: c}
}

func (m *MerkleProofVerifier) VerifyInclusionProof(ctx logger.ContextInterface, kvp KeyValuePair, proof *MerkleInclusionProof, expRootHash TransparencyDigest) (err error) {

	if kvp.Value == nil {
		return NewProofVerificationFailedError(fmt.Errorf("Keys cannot have nil values in the tree"))
	}
	return m.verifyInclusionOrExclusionProof(ctx, kvp, proof, expRootHash)
}

// VerifyExclusionProof uses a MerkleInclusionProof to assert that a specific key is not part of the tree
func (m *MerkleProofVerifier) VerifyExclusionProof(ctx logger.ContextInterface, k Key, proof *MerkleInclusionProof, expRootHash TransparencyDigest) (err error) {
	return m.verifyInclusionOrExclusionProof(ctx, KeyValuePair{Key: k}, proof, expRootHash)
}

// if kvp.Value == nil, this functions checks that kvp.Key is not included in the tree. Otherwise, it checks that kvp is included in the tree.
func (m *MerkleProofVerifier) verifyInclusionOrExclusionProof(ctx logger.ContextInterface, kvp KeyValuePair,
	proof *MerkleInclusionProof, expRootHash TransparencyDigest) (err error) {
	if proof == nil {
		return NewProofVerificationFailedError(fmt.Errorf("nil proof"))
	}

	// First, verify the HiddenKeyValue pair.
	x := new(big.Int)
	x.SetBytes(proof.RootMetadataNoHash.VRFPublicKeyX)
	y := new(big.Int)
	y.SetBytes(proof.RootMetadataNoHash.VRFPublicKeyY)
	vrfPublic := vrf.PublicKey{
		X: x,
		Y: y,
	}
	var hiddenKey []byte
	if !bytes.Equal(proof.VRFProof, []byte("fake")) {
		hiddenKey, err = m.cfg.ECVRF.Verify(&vrfPublic, proof.VRFProof, kvp.Key)
		if err != nil {
			return NewProofVerificationFailedError(err)
		}
	}

	// First verify kvp hashes to root metadata (need to do first to compute exp ztt root hash)
	var kvpHash []byte
	// Hash the key value pair if necessary for inclusion proof
	if kvp.Value != nil {
		encodedValue, _, err := m.cfg.Encoder.EncodeAndHashGeneric(kvp.Value)
		if err != nil {
			return NewProofVerificationFailedError(err)
		}
		kevp := HiddenKeyValuePair{Key: kvp.Key, HiddenKey: hiddenKey, EncodedValue: encodedValue, Entropy: proof.Entropy, AddedAtSeqno: proof.AddedAtSeqno}
		// _, kvpHash, err = m.cfg.Encoder.EncodeAndHashGeneric(kevp)
		// if err != nil {
		// 	return NewProofVerificationFailedError(err)
		// }
		kvpHash = HashPair(kevp)
	}

	if proof.RootMetadataNoHash.RootVersion != RootVersionV1 {
		return NewProofVerificationFailedError(fmt.Errorf("RootVersion %v is not supported (this client can only handle V1)", proof.RootMetadataNoHash.RootVersion))
	}

	if len(hiddenKey) != m.cfg.KeysByteLength {
		return NewProofVerificationFailedError(fmt.Errorf("Key has wrong length for this tree: %v (expected %v)", len(hiddenKey), m.cfg.KeysByteLength))
	}

	// inclusion proofs for existing values can have at most MaxValuesPerLeaf - 1
	// other pairs in the leaf, while exclusion proofs can have at most
	// MaxValuesPerLeaf.
	if (kvp.Value != nil && len(proof.OtherPairsInLeaf)+1 > m.cfg.MaxValuesPerLeaf) || (kvp.Value == nil && len(proof.OtherPairsInLeaf) > m.cfg.MaxValuesPerLeaf) {
		return NewProofVerificationFailedError(fmt.Errorf("Too many keys in leaf: %v > %v", len(proof.OtherPairsInLeaf)+1, m.cfg.MaxValuesPerLeaf))
	}

	// Reconstruct the leaf node if necessary
	var nodeHash []byte
	if kvp.Value != nil || proof.OtherPairsInLeaf != nil {
		valueToInsert := false
		leafHashesLength := len(proof.OtherPairsInLeaf)
		if kvp.Value != nil {
			leafHashesLength++
			valueToInsert = true
		}
		leaf := Node{LeafHashes: make([]KeyHashPair, leafHashesLength)}

		// LeafHashes is obtained by adding kvp into OtherPairsInLeaf while maintaining sorted order
		for i, j := 0, 0; i < leafHashesLength; i++ {
			if (j < len(proof.OtherPairsInLeaf) && valueToInsert && proof.OtherPairsInLeaf[j].HiddenKey.Cmp(hiddenKey) > 0) || j >= len(proof.OtherPairsInLeaf) {
				leaf.LeafHashes[i] = KeyHashPair{HiddenKey: hiddenKey, Hash: kvpHash, AddedAtSeqno: proof.AddedAtSeqno}
				valueToInsert = false
			} else {
				leaf.LeafHashes[i] = proof.OtherPairsInLeaf[j]
				j++
			}

			// Ensure all the KeyHashPairs in the leaf node are different
			if i > 0 && leaf.LeafHashes[i-1].HiddenKey.Cmp(leaf.LeafHashes[i].HiddenKey) >= 0 {
				return NewProofVerificationFailedError(
					fmt.Errorf("Error in Leaf Key ordering or duplicated key: %v >= %v",
						leaf.LeafHashes[i-1].HiddenKey, leaf.LeafHashes[i].HiddenKey))
			}
		}

		// Recompute the hashes on the nodes on the path from the leaf to the root.
		nodeHash = leaf.HashLeafHashes()
	}

	sibH := proof.SiblingHashesOnPath
	if len(sibH)%(m.cfg.ChildrenPerNode-1) != 0 {
		return NewProofVerificationFailedError(fmt.Errorf("Invalid number of SiblingHashes %v", len(sibH)))
	}
	keyAsPos, err := m.cfg.getDeepestPositionForKey(hiddenKey)
	if err != nil {
		return NewProofVerificationFailedError(err)
	}
	leafPosition := m.cfg.getParentAtLevel(keyAsPos, uint(len(sibH)/(m.cfg.ChildrenPerNode-1)))

	// recompute the hash of the root node by recreating all the internal nodes
	// on the path from the leaf to the root.
	i := 0
	for _, childIndex := range m.cfg.positionToChildIndexPath(leafPosition) {
		sibHAtLevel := sibH[i : i+m.cfg.ChildrenPerNode-1]

		node := Node{INodes: make([][]byte, m.cfg.ChildrenPerNode)}
		copy(node.INodes, sibHAtLevel[:int(childIndex)])
		node.INodes[int(childIndex)] = nodeHash
		copy(node.INodes[int(childIndex)+1:], sibHAtLevel[int(childIndex):])

		i += m.cfg.ChildrenPerNode - 1
		nodeHash = node.HashINodes()
	}

	// Compute the hash of the RootMetadata by filling in the BareRootHash
	// with the value computed above.
	rootMetadata := proof.RootMetadataNoHash
	rootMetadata.BareRootHash = nodeHash
	_, rootHash, err := m.cfg.Encoder.EncodeAndHashGeneric(rootMetadata)
	if err != nil {
		return NewProofVerificationFailedError(err)
	}

	// Now hash this up to hthash

	h := rootHash

	idxs := auditProofIndices(rootMetadata.Seqno, rootMetadata.Seqno)

	for i, htSibling := range proof.HtSiblings {

		if isLeftChild(idxs[i], int(rootMetadata.Seqno)*2-1) {
			h = lbbmtHash(htSibling, h)
		} else {
			h = lbbmtHash(h, htSibling)
		}
	}

	// Check the rootHash computed matches the expected value.
	if !hmac.Equal(h, expRootHash) {
		return NewProofVerificationFailedError(
			fmt.Errorf("expected rootHash does not match the computed one (for key: %X, value: %v): expected %x but got %x",
				kvp.Key, kvp.Value, expRootHash, h))
	}

	// Success!
	return nil
}

func hashHistoryTreeUpward(idxs []int, hashes [][]byte, finalSeqno Seqno, limit *Seqno) []byte {
	h := []byte{}
	started := false
	for i, idx := range idxs {
		if limit != nil && idx > (int(*limit)-1)*2 {
			continue
		}
		if !started {
			h = hashes[i]
			started = true
			continue
		}
		h2 := hashes[i]
		if isLeftChild(idx, int(finalSeqno)) {
			h = lbbmtHash(h2, h)
		} else {
			h = lbbmtHash(h, h2)
		}
	}
	return h
}

func verifyExtensionProof(proof *MerkleExtensionProof, initialSeqno Seqno, finalSeqno Seqno,
	initialRootHash TransparencyDigest, finalRootHash TransparencyDigest) error {

	if initialSeqno == finalSeqno {
		if !hmac.Equal(initialRootHash, finalRootHash) {
			return fmt.Errorf("same seqno but hash mismatch")
		}
		return nil
	}

	hashes := proof.HistoryTreeNodeHashes

	// Infer node indices and which way to hash together nodes purely from initialSeqno and finalSeqno.
	idxs := consistencyProofIndices(initialSeqno, finalSeqno)

	// If the initial root is a complete tree, then initialRootHash is part of the extension proof
	// that the server omitted for efficiency, so add it in ourselves.
	if int(initialSeqno) == 1<<log2(int(initialSeqno)) {
		hashes = append([][]byte{initialRootHash}, hashes...)
		idxs = append([]int{int(initialSeqno)*2 - 2}, idxs...)
	}

	// First, ensure that the nodes hash to finalRootHash. We may need to use initialRootHash.
	calc := hashHistoryTreeUpward(idxs, hashes, finalSeqno, nil)
	if !hmac.Equal(finalRootHash, calc) {
		return fmt.Errorf("final hash mismatch")
	}

	// First, ensure that the nodes hash to finalRootHash. We may need to use initialRootHash.
	if !hmac.Equal(initialRootHash, hashHistoryTreeUpward(idxs, hashes, finalSeqno, &initialSeqno)) {
		return fmt.Errorf("initial hash mismatch")
	}

	return nil
}

func (m *MerkleProofVerifier) VerifyExtensionProof(ctx logger.ContextInterface, proof *MerkleExtensionProof, initialSeqno Seqno, initialRootHash TransparencyDigest, finalSeqno Seqno, expRootHash TransparencyDigest) error {
	return verifyExtensionProof(proof, initialSeqno, finalSeqno, initialRootHash, expRootHash)
}
