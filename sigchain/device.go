package sigchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	mathrand "math/rand"
	"net/rpc"
	"time"

	"github.com/mvkdcrypto/mvkd/demo/logger"
	"golang.org/x/sync/errgroup"
)

type Device struct {
	server     *rpc.Client
	userId     []byte
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	clock      *Clock
	players    map[string]*UserSigchainPlayer
}

func NewDevice(server *rpc.Client, userId []byte) (*Device, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Device{
		server:     server,
		userId:     userId,
		publicKey:  publicKey,
		privateKey: privateKey,
		players:    make(map[string]*UserSigchainPlayer),
	}, nil
}

func NewDeterministicDeviceDanger(server *rpc.Client, userId []byte) (*Device, error) {
	var seed int64
	for _, b := range userId {
		seed += int64(b)
	}
	rnd := mathrand.New(mathrand.NewSource(seed))
	publicKey, privateKey, err := ed25519.GenerateKey(rnd)
	if err != nil {
		return nil, err
	}
	return &Device{
		server:     server,
		userId:     userId,
		publicKey:  publicKey,
		privateKey: privateKey,
		players:    make(map[string]*UserSigchainPlayer),
	}, nil
}

func (d *Device) PublicKey() ed25519.PublicKey {
	return d.publicKey
}

func (d *Device) BuildEpochs(ctx logger.ContextInterface, n int) (BuildEpochRet, error) {
	buildEpochArg := BuildEpochArg{N: n}
	buildEpochRet := BuildEpochRet{}

	err := d.server.Call("Server.BuildEpoch", buildEpochArg, &buildEpochRet)
	if err != nil {
		return BuildEpochRet{}, err
	}

	return buildEpochRet, nil
}

func (d *Device) BuildEpoch(ctx logger.ContextInterface, links []Link) (BuildEpochRet, error) {
	buildEpochArg := BuildEpochArg{Links: links}
	buildEpochRet := BuildEpochRet{}

	err := d.server.Call("Server.BuildEpoch", buildEpochArg, &buildEpochRet)
	if err != nil {
		return BuildEpochRet{}, err
	}

	return buildEpochRet, nil
}

func (d *Device) UpdateClock(ctx logger.ContextInterface) error {
	return d.Update(ctx, nil)
}

func (d *Device) UpdateMe(ctx logger.ContextInterface) error {
	return d.Update(ctx, [][]byte{d.userId})
}

func (d *Device) UpdateBench(ctx logger.ContextInterface, userIds [][]byte) (time.Duration, time.Duration, time.Duration, int, int, error) {
	var sinceSeqnos []int
	for _, userId := range userIds {
		sinceSeqnos = append(sinceSeqnos, d.Player(userId).Sigchain.Len())
	}

	queryArg := QueryArg{
		Clock:       d.clock,
		UserIds:     userIds,
		SinceSeqnos: sinceSeqnos,
	}
	queryRet := new(QueryRet)

	st1 := time.Now()
	err := d.server.Call("Server.Query", queryArg, &queryRet)
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	networkTime := time.Since(st1)

	st2 := time.Now()
	clock, err := FastForwardClock(ctx, d.clock, queryRet.LatestEpno, queryRet.LatestDigest, queryRet.ExtensionProof)
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	d.clock = clock

	g := new(errgroup.Group)
	for i, userId := range userIds {
		i, userId := i, userId
		g.Go(func() error {
			player := d.Player(userId)
			err := player.PlayLinks(ctx, clock, queryRet.NewLinks[i], queryRet.InclusionProofs[i], queryRet.ExclusionProofs[i], false)
			if err != nil {
				return err
			}
			return nil
		})
	}
	err = g.Wait()
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	verifyTime := time.Since(st2)

	return networkTime, verifyTime, queryRet.Total, queryRet.ArgBandwidth, queryRet.RetBandwidth, nil
}

func (d *Device) Update(ctx logger.ContextInterface, userIds [][]byte) error {
	_, _, _, _, _, err := d.UpdateBench(ctx, userIds)
	return err
}

func (d *Device) Me() *UserSigchainPlayer {
	return d.Player(d.userId)
}

func (d *Device) Player(userId []byte) *UserSigchainPlayer {
	userIdStr := hex.EncodeToString(userId)
	player, ok := d.players[userIdStr]
	if !ok {
		player = NewUserSigchainPlayer(userId)
		d.players[userIdStr] = player
	}
	return player
}

// Add context in practice
func (d *Device) Sign(o InnerLink) ([]byte, error) {
	m, err := encode(o)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(d.privateKey, m)
	return sig, nil
}

func (d *Device) AddFirstKey() (Link, error) {
	innerLink := UserAddFirstKeyInner{
		Base: Base{
			Id:             d.userId,
			Seqno:          d.Me().Sigchain.Len() + 1,
			LastSeenDigest: d.clock.LastSeenDigest,
			LinkType:       UserLinkTypeAddFirstKey,
			Agent:          d.publicKey,
		},
	}
	sig, err := d.Sign(innerLink)
	if err != nil {
		return Link{}, err
	}

	link := Link{LinkType: UserLinkTypeAddFirstKey, Inner: innerLink, Sigs: [][]byte{sig}}
	return link, nil
}

// Of course in practice, the adder doesn't get access to the subject's private keys
func (d *Device) AddKey(subject *Device) (Link, error) {
	inner := UserAddKeyInner{
		Base: Base{
			Id:             d.userId,
			Seqno:          d.Me().Sigchain.Len() + 1,
			LastSeenDigest: d.clock.LastSeenDigest,
			LinkType:       UserLinkTypeAddKey,
			Agent:          d.publicKey,
		},
		Subject: subject.publicKey,
	}

	agentSig, err := d.Sign(inner)
	if err != nil {
		return Link{}, err
	}

	subjectSig, err := subject.Sign(inner)
	if err != nil {
		return Link{}, err
	}

	link := Link{
		LinkType: inner.Base.LinkType,
		Inner:    inner,
		Sigs:     [][]byte{agentSig, subjectSig},
	}
	return link, nil
}

func (d *Device) Revoke(subject ed25519.PublicKey) (Link, error) {
	innerLink := UserRevokeKeyInner{
		Base: Base{
			Id:             d.userId,
			Seqno:          d.Me().Sigchain.Len() + 1,
			LastSeenDigest: d.clock.LastSeenDigest,
			LinkType:       UserLinkTypeRevokeKey,
			Agent:          d.publicKey,
		},
		Subject: subject,
	}
	sig, err := d.Sign(innerLink)
	if err != nil {
		return Link{}, err
	}

	link := Link{LinkType: UserLinkTypeRevokeKey, Inner: innerLink, Sigs: [][]byte{sig}}
	return link, nil
}

func (d *Device) Extra(extra []byte) (Link, error) {
	innerLink := UserExtraInner{
		Base: Base{
			Id:             d.userId,
			Seqno:          d.Me().Sigchain.Len() + 1,
			LastSeenDigest: d.clock.LastSeenDigest,
			LinkType:       UserLinkTypeExtra,
			Agent:          d.publicKey,
		},
		Extra: extra,
	}
	var sig []byte
	sig, err := d.Sign(innerLink)
	if err != nil {
		return Link{}, err
	}

	link := Link{LinkType: UserLinkTypeExtra, Inner: innerLink, Sigs: [][]byte{sig}}
	return link, nil
}
