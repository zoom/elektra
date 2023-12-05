package merkle

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"testing"

	"github.com/mvkdcrypto/mvkd/demo/msgpack"
	"github.com/mvkdcrypto/mvkd/demo/vrf"
	"github.com/pkg/errors"

	"github.com/stretchr/testify/require"
)

type IdentityVRF struct{}

func (i *IdentityVRF) Params() *vrf.ECVRFParams {
	c := elliptic.P256()
	return &vrf.ECVRFParams{Curve: &c}
}
func (i *IdentityVRF) Prove(sk *vrf.PrivateKey, alpha []byte) []byte {
	return alpha
}

func (i *IdentityVRF) ProofToHash(pi []byte) ([]byte, error) {
	return pi, nil
}

func (i *IdentityVRF) ProofToCurve(pi []byte) (*big.Int, *big.Int, error) {
	return nil, nil, nil
}

func (i *IdentityVRF) Verify(pub *vrf.PublicKey, pi, alpha []byte) ([]byte, error) {
	return alpha, nil
}

func (i *IdentityVRF) StatefulRotate(sk *vrf.PrivateKey, xs [][]byte, oldProofs [][]byte) (sk2 *vrf.PrivateKey, pi vrf.RotationProof, newProofs [][]byte, err error) {

	skBytes, err := RandomBytes(32)
	if err != nil {
		return nil, vrf.RotationProof{}, nil, err
	}
	return vrf.NewKey(*i.Params().Curve, skBytes), vrf.RotationProof{}, nil, nil
}

func (i *IdentityVRF) Rotate(sk *vrf.PrivateKey, xs [][]byte) (sk2 *vrf.PrivateKey, pi vrf.RotationProof, err error) {

	skBytes, err := RandomBytes(32)
	if err != nil {
		return nil, vrf.RotationProof{}, err
	}
	return vrf.NewKey(*i.Params().Curve, skBytes), vrf.RotationProof{}, nil
}

func (i *IdentityVRF) VerifyRotate(pk *vrf.PublicKey, pk2 *vrf.PublicKey, mapping []vrf.RotationMapping, pi vrf.RotationProof) (err error) {
	return nil
}

type SHA2VRF struct{}

func (i *SHA2VRF) Params() *vrf.ECVRFParams {
	c := elliptic.P256()
	return &vrf.ECVRFParams{Curve: &c}
}
func (i *SHA2VRF) Prove(sk *vrf.PrivateKey, alpha []byte) []byte {
	return alpha
}

func (i *SHA2VRF) ProofToHash(pi []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(pi)
	r := h.Sum(nil)
	return r, nil
}

func (i *SHA2VRF) ProofToCurve(pi []byte) (*big.Int, *big.Int, error) {
	return nil, nil, nil
}

func (i *SHA2VRF) Verify(pub *vrf.PublicKey, pi, alpha []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(alpha)
	r := h.Sum(nil)
	return r, nil
}

func (i *SHA2VRF) Rotate(sk *vrf.PrivateKey, xs [][]byte) (sk2 *vrf.PrivateKey, pi vrf.RotationProof, err error) {
	skBytes, err := RandomBytes(32)
	if err != nil {
		return nil, vrf.RotationProof{}, err
	}
	return vrf.NewKey(*i.Params().Curve, skBytes), vrf.RotationProof{}, nil
}

func (i *SHA2VRF) VerifyRotate(pk *vrf.PublicKey, pk2 *vrf.PublicKey, mapping []vrf.RotationMapping, pi vrf.RotationProof) (err error) {
	return nil
}

func newConfigForTest(e Encoder, logChildrenPerNode uint8, maxValuesPerLeaf int,
	keysByteLength int) (Config, error) {
	return NewConfig(e, logChildrenPerNode, maxValuesPerLeaf, keysByteLength,
		ConstructStringValueContainer, &IdentityVRF{})
}

func newConfigForTestWithVRF(e Encoder, logChildrenPerNode uint8,
	maxValuesPerLeaf int) (Config, error) {
	return NewConfig(e, logChildrenPerNode, maxValuesPerLeaf, 32,
		ConstructStringValueContainer, vrf.ECVRFP256SHA256SWU())
}

func makePositionFromStringForTesting(s string) (Position, error) {
	posInt, err := strconv.ParseInt(s, 2, 64)
	if err != nil {
		return Position{}, err
	}
	return (Position)(*big.NewInt(posInt)), nil
}

func getTreeCfgsWith1_2_3BitsPerIndexUnblinded(t *testing.T) (config1bit, config2bits, config3bits Config) {
	config1bit, err := newConfigForTest(IdentityHasher{}, 1, 1, 1)
	require.NoError(t, err)

	config2bits, err = newConfigForTest(IdentityHasher{}, 2, 1, 1)
	require.NoError(t, err)

	config3bits, err = newConfigForTest(IdentityHasher{}, 3, 1, 3)
	require.NoError(t, err)

	return config1bit, config2bits, config3bits
}

func getSampleKVPS3bits() (kvps1, kvps2, kvps3 []KeyValuePair) {
	kvps1 = []KeyValuePair{
		{Key: []byte{0x00, 0x00, 0x00}, Value: "key0x000000Seqno1"},
		{Key: []byte{0x00, 0x00, 0x01}, Value: "key0x000001Seqno1"},
		{Key: []byte{0x00, 0x10, 0x00}, Value: "key0x001000Seqno1"},
		{Key: []byte{0xff, 0xff, 0xff}, Value: "key0xffffffSeqno1"},
	}

	kvps2 = []KeyValuePair{
		{Key: []byte{0x00, 0x00, 0x00}, Value: "key0x000000Seqno2"},
		{Key: []byte{0x00, 0x00, 0x01}, Value: "key0x000001Seqno2"},
		{Key: []byte{0x00, 0x10, 0x00}, Value: "key0x001000Seqno2"},
		{Key: []byte{0xff, 0xff, 0xfe}, Value: "key0xfffffeSeqno2"},
		{Key: []byte{0xff, 0xff, 0xff}, Value: "key0xffffffSeqno2"},
	}

	kvps3 = []KeyValuePair{
		{Key: []byte{0x00, 0x00, 0x00}, Value: "key0x000000Seqno3"},
		{Key: []byte{0x00, 0x00, 0x01}, Value: "key0x000001Seqno3"},
		{Key: []byte{0x00, 0x10, 0x00}, Value: "key0x001000Seqno3"},
		{Key: []byte{0xff, 0xff, 0xfd}, Value: "key0xfffffdSeqno3"},
		{Key: []byte{0xff, 0xff, 0xfe}, Value: "key0xfffffeSeqno3"},
		{Key: []byte{0xff, 0xff, 0xff}, Value: "key0xffffffSeqno3"},
	}
	return kvps1, kvps2, kvps3
}

func getSampleKVPS1bit() (kvps1, kvps2, kvps3 []KeyValuePair) {
	kvps1 = []KeyValuePair{
		{Key: []byte{0x00}, Value: "key0x00Seqno1"},
		{Key: []byte{0x01}, Value: "key0x01Seqno1"},
		{Key: []byte{0x10}, Value: "key0x10Seqno1"},
		{Key: []byte{0xff}, Value: "key0xffSeqno1"},
	}

	kvps2 = []KeyValuePair{
		{Key: []byte{0x00}, Value: "key0x00Seqno2"},
		{Key: []byte{0x01}, Value: "key0x01Seqno2"},
		{Key: []byte{0x10}, Value: "key0x10Seqno2"},
		{Key: []byte{0xfe}, Value: "key0xfeSeqno2"},
		{Key: []byte{0xff}, Value: "key0xffSeqno2"},
	}

	kvps3 = []KeyValuePair{
		{Key: []byte{0x00}, Value: "key0x00Seqno3"},
		{Key: []byte{0x01}, Value: "key0x01Seqno3"},
		{Key: []byte{0x10}, Value: "key0x10Seqno3"},
		{Key: []byte{0xfd}, Value: "key0xfdSeqno3"},
		{Key: []byte{0xfe}, Value: "key0xfeSeqno3"},
		{Key: []byte{0xff}, Value: "key0xffSeqno3"},
	}

	return kvps1, kvps2, kvps3
}

// Useful to debug tests. Hash(b) == b
type IdentityHasher struct{}

var _ Encoder = IdentityHasher{}

func (i IdentityHasher) Encode(o interface{}) (dst []byte, err error) {
	return dst, i.EncodeTo(o, &dst)
}

func (i IdentityHasher) EncodeTo(o interface{}, out *[]byte) (err error) {
	enc, err := msgpack.EncodeCanonical(o)
	if err != nil {
		return err
	}
	*out = append((*out)[:0], enc...)
	return nil
}

func (i IdentityHasher) Decode(dest interface{}, src []byte) error {
	return errors.Wrap(msgpack.Decode(dest, src), "wrap")
}

func (i IdentityHasher) EncodeAndHashGeneric(o interface{}) ([]byte, []byte, error) {
	enc, err := i.Encode(o)
	if err != nil {
		return nil, nil, fmt.Errorf("Encoding error in IdentityHasher for %v: %v", o, err)
	}
	return enc, []byte(enc), nil
}

func (i IdentityHasher) HashGeneric(o interface{}, h *[]byte) (err error) {
	_, *h, err = i.EncodeAndHashGeneric(o)
	return err
}

// returns two disjoint lists of sorted and unique keys of size numPairs1, numPairs2
func MakeRandomKeysForTesting(keysByteLength uint, numPairs1, numPairs2 int) ([]Key, []Key, error) {
	numPairs := numPairs1 + numPairs2

	if keysByteLength < 8 && numPairs > 1<<(keysByteLength*8) {
		return nil, nil, fmt.Errorf("too many keys requested !")
	}

	keyMap := make(map[string]bool, numPairs)
	for len(keyMap) < numPairs {
		key := make([]byte, keysByteLength)
		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
		keyMap[string(key)] = true
	}

	keyStrings1 := make([]string, 0, numPairs1)
	keyStrings2 := make([]string, 0, numPairs2)

	i := 0
	for k := range keyMap {
		if i < numPairs1 {
			keyStrings1 = append(keyStrings1, k)
			i++
		} else {
			keyStrings2 = append(keyStrings2, k)
		}
	}

	sort.Strings(keyStrings1)
	sort.Strings(keyStrings2)

	keys1 := make([]Key, numPairs1)
	for i, k := range keyStrings1 {
		keys1[i] = Key(k)
	}

	keys2 := make([]Key, numPairs2)
	for i, k := range keyStrings2 {
		keys2[i] = Key(k)
	}

	return keys1, keys2, nil
}

func MakeRandomKVPFromKeysForTesting(keys []Key) ([]KeyValuePair, error) {
	kvps := make([]KeyValuePair, len(keys))
	valBuffer := make([]byte, 10)
	for i, key := range keys {
		kvps[i].Key = key
		_, err := rand.Read(valBuffer)
		if err != nil {
			return nil, err
		}
		kvps[i].Value = string(valBuffer)
	}
	return kvps, nil
}

func ConstructStringValueContainer() interface{} {
	return ""
}

type SHA512_256Encoder struct{}

var _ Encoder = SHA512_256Encoder{}

func (e SHA512_256Encoder) Encode(o interface{}) (dst []byte, err error) {
	return dst, e.EncodeTo(o, &dst)
}

func (e SHA512_256Encoder) EncodeTo(o interface{}, out *[]byte) (err error) {
	enc, err := msgpack.EncodeCanonical(o)
	if err != nil {
		return err
	}
	*out = append((*out)[:0], enc...)
	return nil
}

func (e SHA512_256Encoder) Decode(dest interface{}, src []byte) error {
	return errors.Wrap(msgpack.Decode(dest, src), "wrap2")
}

func (e SHA512_256Encoder) EncodeAndHashGeneric(o interface{}) ([]byte, []byte, error) {
	enc, err := e.Encode(o)
	if err != nil {
		return nil, nil, err
	}
	hasher := sha512.New512_256()
	_, err = hasher.Write(enc)
	if err != nil {
		return nil, nil, err
	}
	return enc, hasher.Sum(nil), nil
}

func (e SHA512_256Encoder) HashGeneric(o interface{}, h *[]byte) (err error) {
	_, *h, err = e.EncodeAndHashGeneric(o)
	return err
}

func RandomPairs(m int) ([]KeyValuePair, error) {
	kvps := make([]KeyValuePair, m)
	for i := 0; i < m; i++ {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			return nil, err
		}

		val := make([]byte, 32)
		_, err = rand.Read(val)
		if err != nil {
			return nil, err
		}

		valh := hex.EncodeToString(val)

		kvps[i] = KeyValuePair{Key: key, Value: valh}
	}
	return kvps, nil
}
