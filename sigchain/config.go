package sigchain

import (
	"crypto/sha512"

	"github.com/mvkdcrypto/mvkd/demo/merkle"
	"github.com/mvkdcrypto/mvkd/demo/msgpack"
	"github.com/mvkdcrypto/mvkd/demo/vrf"
)

type SHA512_256Encoder struct{}

var _ merkle.Encoder = SHA512_256Encoder{}

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
	return msgpack.Decode(dest, src)
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

func NewConfig() (merkle.Config, error) {
	valueConstructor := func() interface{} {
		return EncodedLink{}
	}

	return merkle.NewConfig(SHA512_256Encoder{}, 1, 1, 32,
		valueConstructor, vrf.ECVRFP256SHA256SWU())
}
