package sigchain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"

	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/merkle"
	"github.com/mvkdcrypto/mvkd/demo/msgpack"
	"github.com/pkg/errors"
)

type Sigchain []Link

func (s Sigchain) Len() int {
	return len(s)
}

type LinkType int64

const (
	UserLinkTypeAddFirstKey LinkType = 1
	UserLinkTypeAddKey               = 2
	UserLinkTypeRevokeKey            = 3
	UserLinkTypeExtra                = 4
)

type EncodedLink struct {
	LinkType LinkType
	Inner    []byte
	Sigs     [][]byte
}

func (l EncodedLink) Decode() (Link, error) {
	var inner InnerLink
	if l.LinkType == UserLinkTypeAddFirstKey {
		i := &UserAddFirstKeyInner{}
		err := msgpack.Decode(i, l.Inner)
		if err != nil {
			return Link{}, nil
		}
		inner = *i
	} else if l.LinkType == UserLinkTypeAddKey {
		i := &UserAddKeyInner{}
		err := msgpack.Decode(i, l.Inner)
		if err != nil {
			return Link{}, nil
		}
		inner = *i
	} else if l.LinkType == UserLinkTypeRevokeKey {
		i := &UserRevokeKeyInner{}
		err := msgpack.Decode(i, l.Inner)
		if err != nil {
			return Link{}, nil
		}
		inner = *i
	} else if l.LinkType == UserLinkTypeExtra {
		i := &UserExtraInner{}
		err := msgpack.Decode(i, l.Inner)
		if err != nil {
			return Link{}, nil
		}
		inner = *i
	} else {
		return Link{}, fmt.Errorf("unknown link type")
	}
	return Link{LinkType: l.LinkType, Inner: inner, Sigs: l.Sigs}, nil
}

type Link struct {
	LinkType LinkType
	Inner    InnerLink
	Sigs     [][]byte
}

func (l Link) Encode() (EncodedLink, error) {
	m, err := encode(l.Inner)
	if err != nil {
		return EncodedLink{}, err
	}
	return EncodedLink{l.LinkType, m, l.Sigs}, nil
}

type InnerLink interface {
	Label() []byte
	GetBase() Base
	GetAgent() ed25519.PublicKey
}

func init() {
	gob.Register(UserAddFirstKeyInner{})
	gob.Register(UserAddKeyInner{})
	gob.Register(UserRevokeKeyInner{})
	gob.Register(UserExtraInner{})
}

func Label(id []byte, seqno int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(seqno))
	return append(id, b...)
}

type Base struct {
	Id             []byte
	Seqno          int
	LinkType       LinkType
	LastSeenDigest []byte
	Agent          ed25519.PublicKey
}

func (b Base) Label() []byte {
	return Label(b.Id, b.Seqno)
}

func (b Base) GetAgent() ed25519.PublicKey {
	return b.Agent
}

func (b Base) GetBase() Base {
	return b
}

type UserAddFirstKeyInner struct {
	Base
}

var _ InnerLink = UserAddFirstKeyInner{}

type UserAddKeyInner struct {
	Base
	Subject ed25519.PublicKey
}

var _ InnerLink = UserAddKeyInner{}

type UserRevokeKeyInner struct {
	Base
	Subject ed25519.PublicKey
}

var _ InnerLink = UserRevokeKeyInner{}

type UserExtraInner struct {
	Base
	Extra []byte
}

var _ InnerLink = UserExtraInner{}

type Clock struct {
	LastSeenEpno   int
	LastSeenDigest []byte
}

func NewClock() *Clock {
	return &Clock{}
}

func NewClockAt(lastSeenEpno int, lastSeenDigest []byte) *Clock {
	return &Clock{lastSeenEpno, lastSeenDigest}
}

func FastForwardClock(ctx logger.ContextInterface, c *Clock, latestEpno int, latestDigest []byte, proof *merkle.MerkleExtensionProof) (*Clock, error) {
	cfg, err := NewConfig()
	if err != nil {
		panic(err.Error())
	}
	verifier := merkle.NewMerkleProofVerifier(cfg)

	if c == nil {
		return NewClockAt(latestEpno, latestDigest), nil
	}

	if latestEpno < c.LastSeenEpno {
		return nil, fmt.Errorf("epno rollback")
	}
	if latestEpno == c.LastSeenEpno {
		return c, nil // don't allow overwriting of data for same epno
	}

	if c.LastSeenEpno > 0 {
		err = verifier.VerifyExtensionProof(ctx, proof, merkle.Seqno(c.LastSeenEpno), c.LastSeenDigest,
			merkle.Seqno(latestEpno), latestDigest)
		if err != nil {
			return nil, errors.Wrap(err, "failed to verify extension proof")
		}
	}

	return NewClockAt(latestEpno, latestDigest), nil
}

type UserSigchainPlayer struct {
	UserId   []byte
	verifier merkle.MerkleProofVerifier

	Sigchain Sigchain

	ActiveKeys map[string]struct{}
	Extra      []byte
}

func NewUserSigchainPlayer(userId []byte) *UserSigchainPlayer {
	cfg, err := NewConfig()
	if err != nil {
		panic(err.Error())
	}
	verifier := merkle.NewMerkleProofVerifier(cfg)
	return &UserSigchainPlayer{
		UserId:   userId,
		Sigchain: nil,
		verifier: verifier,
	}
}

func (p *UserSigchainPlayer) Serialize() ([]byte, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	err := e.Encode(p)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func DeserializeUserSigchainPlayer(b []byte) (*UserSigchainPlayer, error) {
	cfg, err := NewConfig()
	if err != nil {
		return nil, err
	}
	verifier := merkle.NewMerkleProofVerifier(cfg)

	s := UserSigchainPlayer{}
	e := gob.NewDecoder(bytes.NewReader(b))
	err = e.Decode(&s)
	if err != nil {
		return nil, err
	}
	s.verifier = verifier
	return &s, nil
}

func str(agent ed25519.PublicKey) string {
	return hex.EncodeToString(agent)
}

func isActive(activeKeys map[string]struct{}, agent ed25519.PublicKey) bool {
	_, ok := activeKeys[str(agent)]
	return ok
}

func (p *UserSigchainPlayer) PlayLinks(ctx logger.ContextInterface, clock *Clock, newLinks []Link, proofs []*merkle.MerkleInclusionProof, exclusionProof *merkle.MerkleInclusionProof, asServer bool) error {
	newActiveKeys := make(map[string]struct{})
	for k, v := range p.ActiveKeys {
		newActiveKeys[k] = v
	}
	newExtra := p.Extra

	for idx, newLink := range newLinks {
		var proof *merkle.MerkleInclusionProof
		if !asServer {
			proof = proofs[idx]
		}

		newLinkEncoded, err := newLink.Encode()
		if err != nil {
			return err
		}

		// First perform verifications without modifying state
		kvp := merkle.KeyValuePair{Key: newLink.Inner.Label(), Value: newLinkEncoded}
		if !asServer {
			err = p.verifier.VerifyInclusionProof(ctx, kvp, proof, clock.LastSeenDigest)
			if err != nil {
				return errors.Wrap(err, "failed to verify proof")
			}
		}

		if !hmac.Equal(p.UserId, newLink.Inner.GetBase().Id) {
			return fmt.Errorf("bad id")
		}
		wantedSeqno := p.Sigchain.Len() + idx + 1
		gotSeqno := newLink.Inner.GetBase().Seqno
		if wantedSeqno != gotSeqno {
			return fmt.Errorf("bad seqno; wanted %d; got %d", wantedSeqno, gotSeqno)
		}
		if newLink.Inner.GetBase().LinkType != newLink.LinkType {
			return fmt.Errorf("link type mismatch")
		}

		m, err := encode(newLink.Inner)
		if err != nil {
			return err
		}
		if !ed25519.Verify(newLink.Inner.GetAgent(), m, newLink.Sigs[0]) {
			return fmt.Errorf("bad sig")
		}

		if newLink.Inner.GetBase().Seqno == 1 && newLink.Inner.GetBase().LinkType != UserLinkTypeAddFirstKey {
			return fmt.Errorf("first link must be AddFirstKey")
		}

		if newLink.Inner.GetBase().LinkType == UserLinkTypeAddFirstKey {
			newLinkInner, ok := newLink.Inner.(UserAddFirstKeyInner)
			if !ok {
				return fmt.Errorf("bad link type")
			}

			newActiveKeys = make(map[string]struct{})
			newActiveKeys[str(newLinkInner.Agent)] = struct{}{}
		} else if newLink.Inner.GetBase().LinkType == UserLinkTypeAddKey {
			newLinkInner, ok := newLink.Inner.(UserAddKeyInner)
			if !ok {
				return fmt.Errorf("bad link type")
			}
			if !ed25519.Verify(newLinkInner.Subject, m, newLink.Sigs[1]) {
				return fmt.Errorf("bad subject sig")
			}

			if !isActive(newActiveKeys, newLinkInner.Agent) {
				return fmt.Errorf("agent not active")
			}
			if isActive(newActiveKeys, newLinkInner.Subject) {
				return fmt.Errorf("subject already active")
			}
			newActiveKeys[str(newLinkInner.Subject)] = struct{}{}
		} else if newLink.Inner.GetBase().LinkType == UserLinkTypeRevokeKey {
			newLinkInner, ok := newLink.Inner.(UserRevokeKeyInner)
			if !ok {
				return fmt.Errorf("bad link type")
			}

			if !isActive(newActiveKeys, newLinkInner.Subject) {
				return fmt.Errorf("subject not active")
			}
			delete(newActiveKeys, str(newLinkInner.Subject))
		} else if newLink.Inner.GetBase().LinkType == UserLinkTypeExtra {
			newLinkInner, ok := newLink.Inner.(UserExtraInner)
			if !ok {
				return fmt.Errorf("bad link type")
			}
			if !isActive(newActiveKeys, newLinkInner.Agent) {
				return fmt.Errorf("agent not active")
			}
			newExtra = newLinkInner.Extra
		} else {
			return fmt.Errorf("unknown link type received")
		}
	}

	if !asServer {
		exclusionLabel := Label(p.UserId, p.Sigchain.Len()+len(newLinks)+1)
		err := p.verifier.VerifyExclusionProof(ctx, exclusionLabel, exclusionProof, clock.LastSeenDigest)

		if err != nil {
			return errors.Wrap(err, "excl proof")
		}
	}

	// Now update state after verifications succeed
	p.Sigchain = append(p.Sigchain, newLinks...)
	p.ActiveKeys = newActiveKeys
	p.Extra = newExtra

	return nil
}

func encode(o interface{}) ([]byte, error) {
	return msgpack.EncodeCanonical(o)
}
