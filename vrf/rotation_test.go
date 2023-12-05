package vrf

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func generateMapping(t testing.TB, vrf ECVRF, sk *PrivateKey, sk2 *PrivateKey, xs [][]byte) (ret []RotationMapping) {
	for _, x := range xs {

		ahx, ahy, err := vrf.ProofToCurve(vrf.Prove(sk, x))
		require.NoError(t, err)

		ah2x, ah2y, err := vrf.ProofToCurve(vrf.Prove(sk2, x))
		require.NoError(t, err)

		ret = append(ret, RotationMapping{OldX: ahx, OldY: ahy, NewX: ah2x, NewY: ah2y})
	}
	return
}

func TestRotationSimple(t *testing.T) {
	vrf := ECVRFP256SHA256SWU()

	skbytes := []byte("YELLOWSUBMARINEYELLOWSUBMARINE")
	sk := NewKey(vrf.Params().ec, skbytes)

	xs := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}

	sk2, pi, err := vrf.Rotate(sk, xs)
	require.NoError(t, err)

	mappings := generateMapping(t, vrf, sk, sk2, xs)

	err = vrf.VerifyRotate(&sk.PublicKey, &sk2.PublicKey, mappings, pi)
	require.NoError(t, err)

}

func randomBytes(n int) ([]byte, error) {
	ret := make([]byte, n)
	_, err := rand.Read(ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func benchmarkRotate(b *testing.B, N int) {
	for n := 0; n < b.N; n++ {
		vrf := ECVRFP256SHA256SWU()

		var keys [][]byte
		for i := 0; i < N; i++ {
			buf, err := randomBytes(32)
			require.NoError(b, err)
			keys = append(keys, buf)
		}

		skbytes := []byte("YELLOWSUBMARINEYELLOWSUBMARINE")
		sk := NewKey(vrf.Params().ec, skbytes)

		var sk2 *PrivateKey
		var pi RotationProof
		b.Run(fmt.Sprintf("Rotate"), func(b *testing.B) {
			var err error
			sk2, pi, err = vrf.Rotate(sk, keys)
			require.NoError(b, err)
		})
		mapping := generateMapping(b, vrf, sk, sk2, keys)

		b.Run(fmt.Sprintf("Verify"), func(b *testing.B) {
			err := vrf.VerifyRotate(&sk.PublicKey, &sk2.PublicKey, mapping, pi)
			require.NoError(b, err)
		})
	}
}
func BenchmarkRotate1(b *testing.B) {
	benchmarkRotate(b, 2000)
}
func BenchmarkRotate2(b *testing.B) {
	benchmarkRotate(b, 4000)
}

func BenchmarkRotate3(b *testing.B) {
	benchmarkRotate(b, 6000)
}

func BenchmarkRotate4(b *testing.B) {
	benchmarkRotate(b, 8000)
}

func BenchmarkRotate5(b *testing.B) {
	benchmarkRotate(b, 10000)
}
