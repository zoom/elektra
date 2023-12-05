// Copyright 2020 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vrf

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/mvkdcrypto/mvkd/demo/msgpack"
	"golang.org/x/sync/errgroup"
)

var initonce sync.Once

func initAll() {
	initP256SHA256TAI()
	initP256SHA256SWU()
}

// ECVRFP256SHA256TAI returns a elliptic curve based VRF instantiated with
// P256, SHA256, and the "Try And Increment" strategy for hashing to the curve.
func ECVRFP256SHA256TAI() ECVRF {
	initonce.Do(initAll)
	return p256SHA256TAI
}

// ECVRFP256SHA256SWU returns a elliptic curve based VRF instantiated with
// P256, SHA256, and the Simplified SWU strategy for hashing to the curve.
func ECVRFP256SHA256SWU() ECVRF {
	initonce.Do(initAll)
	return p256SHA256SWU
}

// PublicKey holds a public VRF key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey holds a private VRF key.
type PrivateKey struct {
	PublicKey
	d *big.Int
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() *PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKey) Bytes() []byte {
	return priv.d.Bytes()
}

func NewKey(curve elliptic.Curve, sk []byte) *PrivateKey {
	x, y := curve.ScalarBaseMult(sk)
	return &PrivateKey{
		PublicKey: PublicKey{Curve: curve, X: x, Y: y}, // VRF public key Y = x*B
		d:         new(big.Int).SetBytes(sk),           // Use SK to derive the VRF secret scalar x
	}
}

type RotationMapping struct {
	OldX *big.Int
	OldY *big.Int
	NewX *big.Int
	NewY *big.Int
}

type ECVRF interface {
	Params() *ECVRFParams

	// Prove returns proof pi that beta is the correct hash output.
	// beta is deterministic in the sense that it always
	// produces the same output beta given a pair of inputs (sk, alpha).
	Prove(sk *PrivateKey, alpha []byte) (pi []byte)

	// ProofToHash allows anyone to deterministically obtain the VRF hash
	// output beta directly from the proof value pi.
	//
	// ProofToHash should be run only on pi that is known to have been produced by Prove
	// Clients attempting to verify untrusted inputs should use Verify.
	ProofToHash(pi []byte) (beta []byte, err error)

	ProofToCurve(pi []byte) (x, y *big.Int, err error)

	// Verify that beta is the correct VRF hash of alpha using PublicKey pub.
	Verify(pub *PublicKey, pi, alpha []byte) (beta []byte, err error)

	StatefulRotate(sk *PrivateKey, xs [][]byte, oldProofs [][]byte) (sk2 *PrivateKey, pi RotationProof, newProofs [][]byte, err error)
	Rotate(sk *PrivateKey, xs [][]byte) (sk2 *PrivateKey, pi RotationProof, err error)
	VerifyRotate(pk *PublicKey, pk2 *PublicKey, mapping []RotationMapping, pi RotationProof) (err error)
}

// ECVRFParams holds shared values across ECVRF implementations.
// ECVRFParams also has generic algorithms that rely on ECVRFAux for specific sub algorithms.
type ECVRFParams struct {
	suite    byte // Single nonzero octet specifying the ECVRF ciphersuite.
	Curve    *elliptic.Curve
	ec       elliptic.Curve // Elliptic curve defined over F.
	fieldLen uint           // Length, in bytes, of a field element in F. Defined as 2n in spec.
	ptLen    uint           // Length, in bytes, of an EC point encoded as an octet string.
	qLen     uint           // Length, in bytes, of the prime order of the EC group (Typically ~fieldLen).
	cofactor *big.Int       // The number of points on EC divided by the prime order of the group.
	hash     crypto.Hash    // Cryptographic hash function.
	aux      ECVRFAux       // Suite specific helper functions.
}

func (p *ECVRFParams) EC() elliptic.Curve {
	if p.Curve != nil {
		return *p.Curve
	}
	return p.ec
}

// ECVRFAux contains auxiliary functions necesary for the computation of ECVRF.
type ECVRFAux interface {
	// PointToString converts an EC point to an octet string.
	PointToString(Px, Py *big.Int) []byte

	// StringToPoint converts an octet string to an EC point.
	// This function MUST output INVALID if the octet string does not decode to an EC point.
	StringToPoint(h []byte) (Px, Py *big.Int, err error)

	// IntToString converts a nonnegative integer a to to octet string of length rLen.
	IntToString(x *big.Int, rLen uint) []byte

	// ArbitraryStringToPoint converts an arbitrary 32 byte string s to an EC point.
	ArbitraryStringToPoint(s []byte) (Px, Py *big.Int, err error)

	// HashToCurve is a collision resistant hash of VRF input alpha to H, an EC point in G.
	HashToCurve(Y *PublicKey, alpha []byte) (Hx, Hy *big.Int)

	// GenerateNonoce generates the nonce value k in a deterministic, pseudorandom fashion.
	GenerateNonce(sk *PrivateKey, h []byte) (k *big.Int)
}

// Prove returns proof pi that beta is the correct hash output.
// sk - VRF private key
// alpha - input alpha, an octet string
// Returns pi - VRF proof, octet string of length ptLen+n+qLen
func (p ECVRFParams) Prove(sk *PrivateKey, alpha []byte) []byte {
	// 1.  Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
	// 2.  H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
	Hx, Hy := p.aux.HashToCurve(sk.Public(), alpha) // suite_string is implicitly used in HashToCurve

	// 3.  h_string = point_to_string(H)
	hString := p.aux.PointToString(Hx, Hy)

	// 4.  Gamma = x*H
	Gx, Gy := p.ec.ScalarMult(Hx, Hy, sk.d.Bytes())

	// 5.  k = ECVRF_nonce_generation(SK, h_string)
	k := p.aux.GenerateNonce(sk, hString)

	// 6.  c = ECVRF_hash_points(H, Gamma, k*B, k*H)
	Ux, Uy := p.ec.ScalarBaseMult(k.Bytes())
	Vx, Vy := p.ec.ScalarMult(Hx, Hy, k.Bytes())
	c := p.hashPoints(Hx, Hy, Gx, Gy, Ux, Uy, Vx, Vy)

	// 7.  s = (k + c*x) mod q
	s := new(big.Int).Mul(c, sk.d)
	s.Add(k, s)
	s.Mod(s, p.ec.Params().N)

	// 8.  pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
	pi := new(bytes.Buffer)
	pi.Write(p.aux.PointToString(Gx, Gy))
	pi.Write(p.aux.IntToString(c, p.fieldLen/2)) // 2n = fieldLen
	pi.Write(p.aux.IntToString(s, p.qLen))

	return pi.Bytes()
}

// ProofToHash returns VRF hash output beta from VRF proof pi.
//
// Input: pi - VRF proof, octet string of length ptLen+n+qLen
// Output: beta - VRF hash output, octet string of length hLen or "INVALID"
//
// ProofToHash should be run only on pi that is known to have been produced by
// Prove, or from within Verify.
//
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.2
func (p ECVRFParams) ProofToHash(pi []byte) (beta []byte, err error) {
	// 1.  D = ECVRF_decode _proof(pi_string)
	Gx, Gy, _, _, err := p.decodeProof(pi)
	// 2.  If D is "INVALID", output "INVALID" and stop
	if err != nil {
		return nil, err
	}

	// 3.  (Gamma, c, s) = D
	// 4.  three_string = 0x03 = int_to_string(3, 1), a single octet with value 3

	// 5.  beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
	h := p.hash.New()
	h.Write([]byte{p.suite, 0x03})
	h.Write(p.aux.PointToString(p.ec.ScalarMult(Gx, Gy, p.cofactor.Bytes())))

	// 6.  Output beta_string
	return h.Sum(nil), nil
}

func (p ECVRFParams) ProofToCurve(pi []byte) (x, y *big.Int, err error) {
	// TODO do we need to multiply by cofactor?

	// 1.  D = ECVRF_decode _proof(pi_string)
	Gx, Gy, _, _, err := p.decodeProof(pi)
	// 2.  If D is "INVALID", output "INVALID" and stop
	if err != nil {
		return nil, nil, err
	}
	return Gx, Gy, nil
}

// Verify that beta is the correct VRF hash of alpha using PublicKey pub.
//
// Input:
//
//	pub - public key, an EC point
//	pi_string - VRF proof, octet string of length ptLen+n+qLen
//	alpha_string - VRF input, octet string
//
// Output:
//
//	beta, the VRF hash output, octet string of length hLen; or "INVALID"
func (p ECVRFParams) Verify(pub *PublicKey, pi, alpha []byte) (beta []byte, err error) {
	// 1.  D = ECVRF_decode_proof(pi_string)
	Gx, Gy, c, s, err := p.decodeProof(pi)
	// 2.  If D is "INVALID", output "INVALID" and stop
	if err != nil {
		return nil, err
	}
	// 3.  (Gamma, c, s) = D

	// 4.  H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
	Hx, Hy := p.aux.HashToCurve(pub, alpha)

	// 5.  U = s*B - c*Y
	U1x, U1y := p.ec.ScalarBaseMult(s.Bytes())
	U2x, U2y := p.ec.ScalarMult(pub.X, pub.Y, c.Bytes())
	rev := new(big.Int).Neg(U2y)
	rev = rev.Mod(rev, p.ec.Params().P)
	Ux, Uy := p.ec.Add(U1x, U1y, U2x, rev) // -(U2x, U2y) = (U2x, -U2y)

	// 6.  V = s*H - c*Gamma
	V1x, V1y := p.ec.ScalarMult(Hx, Hy, s.Bytes())
	V2x, V2y := p.ec.ScalarMult(Gx, Gy, c.Bytes())
	rev2 := new(big.Int).Neg(V2y)
	rev2 = rev2.Mod(rev2, p.ec.Params().P)
	Vx, Vy := p.ec.Add(V1x, V1y, V2x, rev2)

	// 7.  c' = ECVRF_hash_points(H, Gamma, U, V)
	cPrime := p.hashPoints(Hx, Hy, Gx, Gy, Ux, Uy, Vx, Vy)

	// 8.  If c and c' are not equal output "INVALID"
	if c.Cmp(cPrime) != 0 {
		return nil, errors.New("invalid cprime")
	}
	// else, output (ECVRF_proof_to_hash(pi_string), "VALID")
	return p.ProofToHash(pi)
}

//
// Auxiliary functions
//

// hashPoints accepts X,Y pairs of EC points in G and returns an hash value between 0 and 2^(8n)-1
//
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.4.3
func (p ECVRFParams) hashPoints(pm ...*big.Int) (c *big.Int) {
	if len(pm)%2 != 0 {
		panic("odd number of inputs")
	}
	// 1.  two_string = 0x02 = int_to_string(2, 1), a single octet with value 2
	// 2.  Initialize str = suite_string || two_string
	str := []byte{p.suite, 0x02}

	// 3.  for PJ in [P1, P2, ... PM]:
	for i := 0; i < len(pm); i += 2 {
		// str = str || point_to_string(PJ)
		str = append(str, p.aux.PointToString(pm[i], pm[i+1])...)
	}

	// 4.  c_string = Hash(str)
	hc := p.hash.New()
	hc.Write(str)
	cString := hc.Sum(nil)

	// 5.  truncated_c_string = c_string[0]...c_string[n-1]
	n := p.fieldLen / 2 //   2n = fieldLen = 32
	// 6.  c = string_to_int(truncated_c_string)
	c = new(big.Int).SetBytes(cString[:n])
	return c
}

// decodeProof
//
// Input: pi_string - VRF proof, octet string (ptLen+n+qLen octets)
//
// Output:
//
//	Gx, Gy - Gamma - EC point
//	c - integer between 0 and 2^(8n)-1
//	s - integer between 0 and 2^(8qLen)-1
//	or "INVALID"
//
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.4.4
func (p ECVRFParams) decodeProof(pi []byte) (Gx, Gy, c, s *big.Int, err error) {
	n := p.fieldLen / 2
	if got, want := uint(len(pi)), p.ptLen+n+p.qLen; got != want {
		return nil, nil, nil, nil, fmt.Errorf("len(pi): %v, want %v", got, want)
	}

	//    1.  let gamma_string = pi_string[0]...p_string[ptLen-1]
	gStr := pi[:p.ptLen]
	//    2.  let c_string = pi_string[ptLen]...pi_string[ptLen+n-1]
	cStr := pi[p.ptLen : p.ptLen+n]
	//    3.  let s_string =pi_string[ptLen+n]...pi_string[ptLen+n+qLen-1]
	sStr := pi[p.ptLen+n:]

	//    4.  Gamma = string_to_point(gamma_string)
	Gx, Gy, err = p.aux.StringToPoint(gStr)
	//    5.  if Gamma = "INVALID" output "INVALID" and stop.
	if err != nil || Gx == nil || Gy == nil {
		return nil, nil, nil, nil, fmt.Errorf("aux.StringToPoint() failed: %w", err)
	}

	//    6.  c = string_to_int(c_string)
	c = new(big.Int).SetBytes(cStr)
	//    7.  s = string_to_int(s_string)
	s = new(big.Int).SetBytes(sStr)
	//    8.  Output Gamma, c, and s
	return Gx, Gy, c, s, nil
}

func (p ECVRFParams) hashToFieldElement(x []byte) *big.Int {
	// 4.  c_string = Hash(str)
	hc := p.hash.New()
	hc.Write(x)
	cString := hc.Sum(nil)

	// 5.  truncated_c_string = c_string[0]...c_string[n-1]
	n := p.fieldLen / 2 //   2n = fieldLen = 32
	// 6.  c = string_to_int(truncated_c_string)
	c := new(big.Int).SetBytes(cString[:n])
	return c
}

func (p ECVRFParams) truncateToFieldElement(x []byte) *big.Int {
	n := p.fieldLen / 2 //   2n = fieldLen = 32
	c := new(big.Int).SetBytes(x[:n])
	return c
}

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

// adapted from crypto/elliptic.GenerateKey
func (p ECVRFParams) randomFieldElement() (n *big.Int) {
	N := p.ec.Params().N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) / 8

	rnd := make([]byte, byteLen)

	for {
		_, err := io.ReadFull(rand.Reader, rnd)
		if err != nil {
			return
		}
		// We have to mask off any excess bits in the case that the size of the
		// underlying field is not a whole number of bytes.
		rnd[0] &= mask[bitSize%8]

		// If the scalar is out of range, sample another random number.
		n = new(big.Int).SetBytes(rnd)
		if n.Cmp(N) < 0 {
			return n
		}
	}
}

func msgpackEncode(o interface{}) (dst []byte, err error) {
	return dst, msgpackEncodeTo(o, &dst)
}

func msgpackEncodeTo(o interface{}, out *[]byte) (err error) {
	enc, err := msgpack.EncodeCanonical(o)
	if err != nil {
		return err
	}
	*out = append((*out)[:0], enc...)
	return nil
}

type cstruct struct {
	pk PublicKey
	yX *big.Int
	yY *big.Int

	pk2    PublicKey
	y2X    *big.Int
	y2Y    *big.Int
	pkexpX *big.Int
	pkexpY *big.Int
	yexpX  *big.Int
	yexpY  *big.Int
}

type RotationProof struct {
	PkExpX *big.Int
	PkExpY *big.Int
	YExpX  *big.Int
	YExpY  *big.Int
	Z      *big.Int
}

func (p ECVRFParams) encodeAndHash(o interface{}) ([]byte, error) {
	ser, err := msgpackEncode(o)
	if err != nil {
		return nil, err
	}
	wr := p.hash.New()
	wr.Write(ser)
	return wr.Sum(nil), nil
}

func (p ECVRFParams) Rotate(sk *PrivateKey, xs [][]byte) (sk2 *PrivateKey, pi RotationProof, err error) {
	sk2, pi, _, err = p.StatefulRotate(sk, xs, nil)
	return sk2, pi, err
}

func (p ECVRFParams) StatefulRotate(sk *PrivateKey, xs [][]byte, oldProofs [][]byte) (sk2 *PrivateKey, pi RotationProof, newProofs [][]byte, err error) {
	alpha := p.randomFieldElement()
	sk2d := new(big.Int)
	sk2d.Mul(sk.d, alpha)
	sk2 = NewKey(p.ec, sk2d.Bytes())

	newProofs = make([][]byte, len(xs))
	mappings := make([]RotationMapping, len(xs))
	g := new(errgroup.Group)
	g.SetLimit(32)
	for i, x := range xs {
		i, x := i, x
		g.Go(func() error {
			var oldx, oldy *big.Int
			if len(oldProofs) == 0 {
				var err error
				oldx, oldy, err = p.ProofToCurve(p.Prove(sk, x))
				if err != nil {
					return err
				}
			} else {
				var err error
				oldx, oldy, err = p.ProofToCurve(oldProofs[i])
				if err != nil {
					return err
				}

			}
			newProof := p.Prove(sk2, x)
			newx, newy, err := p.ProofToCurve(newProof)
			if err != nil {
				return err
			}
			newProofs[i] = newProof
			mappings[i] = RotationMapping{
				OldX: oldx,
				OldY: oldy,
				NewX: newx,
				NewY: newy,
			}
			return err
		})
	}
	err = g.Wait()
	if err != nil {
		return nil, RotationProof{}, nil, err
	}

	mappingsHash, err := p.encodeAndHash(mappings)
	if err != nil {
		return nil, RotationProof{}, nil, err
	}

	var as []*big.Int
	for idx, _ := range xs {
		inp := mappings[idx].OldX.Bytes()
		inp = append(inp, mappings[idx].OldY.Bytes()...)
		inp = append(inp, sk.Public().X.Bytes()...)
		inp = append(inp, sk.Public().Y.Bytes()...)
		inp = append(inp, sk2.Public().X.Bytes()...)
		inp = append(inp, sk2.Public().Y.Bytes()...)
		inp = append(inp, mappingsHash...)
		as = append(as, p.hashToFieldElement(inp))
	}

	r := p.randomFieldElement()
	pkexpX, pkexpY := p.ec.ScalarMult(sk.Public().X, sk.Public().Y, r.Bytes())

	yX, yY, y2X, y2Y, err := p.combineY(mappings, as)
	if err != nil {
		return nil, RotationProof{}, nil, err
	}

	yexpX, yexpY := p.ec.ScalarMult(yX, yY, r.Bytes())
	cst := cstruct{
		pk:     *sk.Public(),
		yX:     yX,
		yY:     yY,
		pk2:    *sk2.Public(),
		y2X:    y2X,
		y2Y:    y2Y,
		pkexpX: pkexpX,
		pkexpY: pkexpY,
		yexpX:  yexpX,
		yexpY:  yexpY,
	}
	cbytes, err := p.encodeAndHash(cst)
	if err != nil {
		return nil, RotationProof{}, nil, err
	}
	c := p.truncateToFieldElement(cbytes)

	zint := new(big.Int)
	z := new(big.Int)
	zint.Mul(c, alpha).Mod(zint, p.ec.Params().N)
	z.Sub(r, zint).Mod(z, p.ec.Params().N)
	proof := RotationProof{
		PkExpX: pkexpX,
		PkExpY: pkexpY,
		YExpX:  yexpX,
		YExpY:  yexpY,
		Z:      z,
	}

	return sk2, proof, newProofs, nil
}

func (p ECVRFParams) combineY(mappings []RotationMapping, as []*big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	mXs := make([]*big.Int, len(mappings))
	mYs := make([]*big.Int, len(mappings))
	m2Xs := make([]*big.Int, len(mappings))
	m2Ys := make([]*big.Int, len(mappings))
	g := new(errgroup.Group)
	g.SetLimit(32)
	for idx, mapping := range mappings {
		idx, mapping := idx, mapping
		g.Go(func() error {
			mX, mY := p.ec.ScalarMult(mapping.OldX, mapping.OldY, as[idx].Bytes())
			m2X, m2Y := p.ec.ScalarMult(mapping.NewX, mapping.NewY, as[idx].Bytes())
			mXs[idx] = mX
			mYs[idx] = mY
			m2Xs[idx] = m2X
			m2Ys[idx] = m2Y
			return nil
		})
	}
	err := g.Wait()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	yX := big.NewInt(0)
	yY := big.NewInt(0)
	y2X := big.NewInt(0)
	y2Y := big.NewInt(0)
	for i, _ := range mXs {
		yX, yY = p.ec.Add(yX, yY, mXs[i], mYs[i])
		y2X, y2Y = p.ec.Add(y2X, y2Y, m2Xs[i], m2Ys[i])
	}
	return yX, yY, y2X, y2Y, nil
}

func (p ECVRFParams) VerifyRotate(pk *PublicKey, pk2 *PublicKey, mappings []RotationMapping, pi RotationProof) (err error) {

	invalidx, invalidy := p.ec.ScalarBaseMult(big.NewInt(0).Bytes())

	if pk.X == invalidx && pk.Y == invalidy {
		return fmt.Errorf("old pk invalid")
	}
	if pk2.X == invalidx && pk2.Y == invalidy {
		return fmt.Errorf("new pk invalid")
	}

	mappingsHash, err := p.encodeAndHash(mappings)
	if err != nil {
		return err
	}

	var as []*big.Int
	for _, mapping := range mappings {
		inp := mapping.OldX.Bytes()
		inp = append(inp, mapping.OldY.Bytes()...)
		inp = append(inp, pk.X.Bytes()...)
		inp = append(inp, pk.Y.Bytes()...)
		inp = append(inp, pk2.X.Bytes()...)
		inp = append(inp, pk2.Y.Bytes()...)
		inp = append(inp, mappingsHash...)
		as = append(as, p.hashToFieldElement(inp))
	}

	yX, yY, y2X, y2Y, err := p.combineY(mappings, as)
	if err != nil {
		return err
	}

	cst := cstruct{
		pk:     *pk,
		yX:     yX,
		yY:     yY,
		pk2:    *pk2,
		y2X:    y2X,
		y2Y:    y2Y,
		pkexpX: pi.PkExpX,
		pkexpY: pi.PkExpY,
		yexpX:  pi.YExpX,
		yexpY:  pi.YExpY,
	}
	cbytes, err := p.encodeAndHash(cst)
	if err != nil {
		return err
	}
	c := p.truncateToFieldElement(cbytes)

	h1p1x, h1p1y := p.ec.ScalarMult(pk.X, pk.Y, pi.Z.Bytes())
	h1p2x, h1p2y := p.ec.ScalarMult(pk2.X, pk2.Y, c.Bytes())
	h1x, h1y := p.ec.Add(h1p1x, h1p1y, h1p2x, h1p2y)
	if pi.PkExpX.Cmp(h1x) != 0 {
		return fmt.Errorf("bad h1 x %x != %x", pi.PkExpX, h1x)
	}
	if pi.PkExpY.Cmp(h1y) != 0 {
		return fmt.Errorf("bad h1 y")
	}

	h2p1x, h2p1y := p.ec.ScalarMult(yX, yY, pi.Z.Bytes())
	h2p2x, h2p2y := p.ec.ScalarMult(y2X, y2Y, c.Bytes())
	h2x, h2y := p.ec.Add(h2p1x, h2p1y, h2p2x, h2p2y)
	if pi.YExpX.Cmp(h2x) != 0 {
		return fmt.Errorf("bad h2 x %x != %x", pi.YExpX, h2x)
	}
	if pi.YExpY.Cmp(h2y) != 0 {
		return fmt.Errorf("bad h2 y")
	}
	return nil
}

func GenerateMapping(vrf ECVRF, sk *PrivateKey, sk2 *PrivateKey, xs [][]byte) ([]RotationMapping, error) {
	ret := make([]RotationMapping, 0, len(xs))
	for _, x := range xs {
		ahx, ahy, err := vrf.ProofToCurve(vrf.Prove(sk, x))
		if err != nil {
			return nil, err
		}

		ah2x, ah2y, err := vrf.ProofToCurve(vrf.Prove(sk2, x))
		if err != nil {
			return nil, err
		}

		ret = append(ret, RotationMapping{OldX: ahx, OldY: ahy, NewX: ah2x, NewY: ah2y})
	}
	return ret, nil
}
