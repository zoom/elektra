package sigchain

import (
	"bytes"
	"context"
	"crypto/rand"
	cryptorand "crypto/rand"
	"encoding/gob"
	"fmt"
	"net"
	"net/http"
	"net/rpc"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/merkle"
	"github.com/mvkdcrypto/mvkd/demo/storage"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	cfg  merkle.Config
	tree *merkle.Tree
}

func (s *Server) run(f func(tr *sqlx.Tx) error) error {
	switch eng := s.tree.Eng().(type) {
	case *storage.MerkleStorageEngine:
		tx := eng.Tx()
		err := f(tx)
		if err != nil {
			tx.Rollback()
			return err
		} else {
			err := tx.Commit()
			if err != nil {
				return err
			}
			return nil
		}

		// defer func() {
		// 	if p := recover(); p != nil {
		// 		tx.Rollback()
		// 		panic(p)
		// 	}
		// 	err := tx.Commit()
		// 	if err != nil {
		// 		panic(err.Error())
		// 	}
		// }()
		// return f(tx)
	default:
		return f(nil)
	}
}

func NewServer(ctx logger.ContextInterface, eng merkle.StorageEngine) (*Server, error) {
	cfg, err := NewConfig()
	if err != nil {
		return nil, err
	}
	step := 1
	v := merkle.RootVersionV1
	tree, err := merkle.NewTree(cfg, step, eng, v)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:  cfg,
		tree: tree,
	}
	return s, nil
}

func newPostgresEngine(cfg merkle.Config, treeId []byte) (*storage.MerkleStorageEngine, error) {
	db, err := sqlx.Open("postgres", "user=foo dbname=merkle sslmode=disable")
	if err != nil {
		return nil, err
	}
	return storage.NewMerkleStorageEngine(db, cfg, treeId), nil
}

func NewServerWithPostgres(ctx logger.ContextInterface, treeId []byte) (*Server, error) {
	cfg, err := NewConfig()
	if err != nil {
		return nil, err
	}
	eng, err := newPostgresEngine(cfg, treeId)
	if err != nil {
		return nil, err
	}
	s, err := NewServer(ctx, eng)
	if err != nil {
		return nil, err
	}
	return s, nil
}

type InitializeArg struct {
	NLinks int
	Fake   bool
}
type InitializeRet struct{}

func (s *Server) Initialize(arg InitializeArg, ret *InitializeRet) error {
	ctx := logger.NewContext(context.TODO(), logger.NewNull())
	return s.Bootstrap(ctx, arg.NLinks, arg.Fake)
}

type QueryArg struct {
	Clock       *Clock
	UserIds     [][]byte
	SinceSeqnos []int
}

type QueryRet struct {
	LatestEpno      int
	LatestDigest    []byte
	ExtensionProof  *merkle.MerkleExtensionProof
	NewLinks        [][]Link
	InclusionProofs [][]*merkle.MerkleInclusionProof
	ExclusionProofs []*merkle.MerkleInclusionProof
	Total           time.Duration
	ArgBandwidth    int
	RetBandwidth    int
}

func measureBandwidth(x interface{}) (int, error) {
	var network bytes.Buffer
	enc := gob.NewEncoder(&network)
	err := enc.Encode(x)
	if err != nil {
		return 0, err
	}
	return network.Len(), nil
}

func (s *Server) Query(arg QueryArg, ret *QueryRet) error {
	ctx := logger.NewContext(context.TODO(), logger.NewNull())
	st := time.Now()
	epno, digest, extpf, links, incl, excl, err := s.query(ctx, arg.Clock, arg.UserIds, arg.SinceSeqnos, false)
	if err != nil {
		return err
	}
	el := time.Since(st)

	ret.LatestEpno = epno
	ret.LatestDigest = digest
	ret.ExtensionProof = extpf
	ret.NewLinks = links
	ret.InclusionProofs = incl
	ret.ExclusionProofs = excl
	ret.Total = el

	argBandwidth, err := measureBandwidth(arg)
	if err != nil {
		return err
	}
	retBandwidth, err := measureBandwidth(ret)
	if err != nil {
		return err
	}

	ret.ArgBandwidth = argBandwidth
	ret.RetBandwidth = retBandwidth

	return nil
}

type BuildEpochArg struct {
	Links []Link
	N     int
}

type BuildEpochRet struct {
	Total  time.Duration
	Verify time.Duration
	VRF    time.Duration
	Build  time.Duration
}

func (s *Server) BuildEpoch(arg BuildEpochArg, ret *BuildEpochRet) error {
	ctx := logger.NewContext(context.TODO(), logger.NewNull())
	st := time.Now()

	if arg.N == 0 {
		verify, vrf, build, err := s.buildEpoch(ctx, arg.Links)
		if err != nil {
			return err
		}
		total := time.Since(st)
		ret.Total = total
		ret.Verify = verify
		ret.VRF = vrf
		ret.Build = build
		return nil
	} else {
		for i := 0; i < arg.N; i++ {
			_, _, _, err := s.buildEpoch(ctx, nil)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func (s *Server) buildEpoch(ctx logger.ContextInterface, links []Link) (time.Duration, time.Duration, time.Duration, error) {
	var kvps []merkle.KeyValuePair

	epno, digest, err := s.latestRoot(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	clock := NewClockAt(epno, digest)

	var ids [][]byte
	for _, link := range links {
		ids = append(ids, link.Inner.GetBase().Id)
	}

	players, err := s.getPlayers(ctx, ids)
	if err != nil {
		return 0, 0, 0, err
	}

	verifySt := time.Now()
	g := new(errgroup.Group)
	for i, player := range players {
		i, player := i, player
		g.Go(func() error {
			link := links[i]
			err = player.PlayLinks(ctx, clock, []Link{link}, nil, nil, true)
			if err != nil {
				return err
			}
			return nil
		})
	}
	err = g.Wait()
	if err != nil {
		return 0, 0, 0, err
	}
	verify := time.Since(verifySt)

	// encSt := time.Now()
	for i, _ := range players {
		link := links[i]
		encodedLink, err := link.Encode()
		if err != nil {
			return 0, 0, 0, err
		}
		label := link.Inner.Label()
		kvp := merkle.KeyValuePair{
			Key:   label,
			Value: encodedLink,
		}
		kvps = append(kvps, kvp)
	}
	// encEl := time.Since(encSt)

	// setSt := time.Now()
	err = s.setPlayers(ctx, ids, players)
	if err != nil {
		return 0, 0, 0, err
	}
	// setEl := time.Since(setSt)

	buildSt := time.Now()
	err = s.run(func(tr *sqlx.Tx) error {
		_, _, err := s.tree.Build(ctx, tr, kvps, nil, false)
		return err
	})
	if err != nil {
		return 0, 0, 0, err
	}
	build := time.Since(buildSt)
	buildVRF := s.tree.LastHideEl

	return verify, buildVRF, build - buildVRF, nil
}

type RotateArg struct{}
type RotateRet struct {
	Total time.Duration
	VRF   time.Duration
	Build time.Duration
}

func (s *Server) Rotate(arg RotateArg, ret *RotateRet) error {
	ctx := logger.NewContext(context.TODO(), logger.NewNull())
	st := time.Now()
	err := s.run(func(tr *sqlx.Tx) error {
		_, _, err := s.tree.Rotate(ctx, tr, nil)
		return err
	})
	if err != nil {
		return err
	}
	el := time.Since(st)
	ret.Total = el
	ret.VRF = s.tree.LastRotateVRFEl
	ret.Build = s.tree.LastRotateBuildEl
	return nil
}

func randomLinks(m int) ([]merkle.KeyValuePair, error) {
	kvps := make([]merkle.KeyValuePair, m)
	for i := 0; i < m; i++ {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			return nil, err
		}

		val := Link{}

		kvps[i] = merkle.KeyValuePair{Key: key, Value: val}
	}
	return kvps, nil
}
func (s *Server) Bootstrap(ctx logger.ContextInterface, n int, fake bool) error {
	if n == 0 {
		return s.run(func(tr *sqlx.Tx) error {
			_, _, err := s.tree.Build(ctx, tr, nil, nil, fake)
			return err
		})
	}
	if n < 99 {
		return fmt.Errorf("min 100 to initialize")
	}

	batchsize := 100
	for i := 0; i < n/batchsize; i++ {
		if i%500 == 499 {
			fmt.Printf("Initialization progress: %d\n", i*batchsize)
		}
		kvps, err := randomLinks(batchsize)
		if err != nil {
			return err
		}
		err = s.run(func(tr *sqlx.Tx) error {
			_, _, err = s.tree.Build(ctx, tr, kvps, nil, fake)
			return errors.Wrap(err, "wrap")
		})
		if err != nil {
			return errors.Wrap(err, "wrap")
		}
	}

	return nil
}

func (s *Server) query(ctx logger.ContextInterface, clock *Clock, ids [][]byte, sinceSeqnos []int, asServer bool) (int, []byte, *merkle.MerkleExtensionProof, [][]Link, [][]*merkle.MerkleInclusionProof, []*merkle.MerkleInclusionProof, error) {
	var atEpno int
	var hash []byte
	var pf *merkle.MerkleExtensionProof
	if clock == nil {
		var err error
		atEpno, hash, err = s.latestRoot(ctx)
		if err != nil {
			return 0, nil, nil, nil, nil, nil, err
		}
	} else {
		var err error
		atEpno, hash, pf, err = s.updateView(ctx, clock.LastSeenEpno)
		if err != nil {
			return 0, nil, nil, nil, nil, nil, err
		}
	}

	linkRet := make([][]Link, len(ids))
	inclRet := make([][]*merkle.MerkleInclusionProof, len(ids))
	exclRet := make([]*merkle.MerkleInclusionProof, len(ids))

	g := new(errgroup.Group)
	for i, id := range ids {
		i, id := i, id
		g.Go(func() error {
			links, incl, excl, err := s.querySigchain(ctx, id, atEpno, sinceSeqnos[i], asServer)
			if err != nil {
				return err
			}
			linkRet[i] = links
			inclRet[i] = incl
			exclRet[i] = excl
			return nil
		})
	}
	err := g.Wait()
	if err != nil {
		return 0, nil, nil, nil, nil, nil, err
	}

	return atEpno, hash, pf, linkRet, inclRet, exclRet, nil
}

func (s *Server) latestRoot(ctx logger.ContextInterface) (int, []byte, error) {
	var rlatestEpno int
	var rdigest []byte
	err := s.run(func(tr *sqlx.Tx) error {
		latestEpno, _, digest, err := s.tree.GetLatestRoot(ctx, tr)
		if err != nil {
			return err
		}

		rlatestEpno = int(latestEpno)
		rdigest = digest
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return rlatestEpno, rdigest, nil
}

func (s *Server) updateView(ctx logger.ContextInterface, sinceEpno int) (int, []byte, *merkle.MerkleExtensionProof, error) {
	var rlatestEpno int
	var rdigest []byte
	var rproof *merkle.MerkleExtensionProof
	err := s.run(func(tr *sqlx.Tx) error {
		latestEpno, _, digest, err := s.tree.GetLatestRoot(ctx, tr)
		if err != nil {
			return err
		}

		if merkle.Seqno(sinceEpno) == latestEpno {
			rlatestEpno = sinceEpno
			rdigest = digest
			rproof = nil
			return nil
		}

		var proof merkle.MerkleExtensionProof
		if sinceEpno > 0 {
			proof, err = s.tree.GetExtensionProof(ctx, tr, merkle.Seqno(sinceEpno), latestEpno)
			if err != nil {
				return err
			}
		}

		rlatestEpno = int(latestEpno)
		rdigest = digest
		rproof = &proof
		return nil
	})
	if err != nil {
		return 0, nil, nil, err
	}
	return rlatestEpno, rdigest, rproof, nil
}

func (s *Server) querySigchain(ctx logger.ContextInterface, id []byte, atEpno int, sinceSeqno int, asServer bool) ([]Link, []*merkle.MerkleInclusionProof, *merkle.MerkleInclusionProof, error) {
	var newLinks []Link
	var proofs []*merkle.MerkleInclusionProof
	idx := sinceSeqno + 1

	for {
		label := Label(id, idx)

		var ok bool
		var encodedLink interface{}
		var proof merkle.MerkleInclusionProof

		err := s.run(func(tr *sqlx.Tx) error {
			var err error
			if asServer {
				ok, encodedLink, err = s.tree.QueryKeyUnsafe(ctx, tr, merkle.Seqno(atEpno), label)
			} else {
				ok, encodedLink, proof, err = s.tree.QueryKey(ctx, tr, merkle.Seqno(atEpno), label)
			}
			return errors.Wrap(err, "query key err")
		})
		if !ok {
			return newLinks, proofs, &proof, nil
		}

		link, err := encodedLink.(EncodedLink).Decode()
		if err != nil {
			return newLinks, proofs, nil, err
		}
		newLinks = append(newLinks, link)
		proofs = append(proofs, &proof)
		idx++
	}
}

func (s *Server) getPlayers(ctx logger.ContextInterface, ids [][]byte) ([]*UserSigchainPlayer, error) {
	players := make([]*UserSigchainPlayer, len(ids))
	var playersb [][]byte
	err := s.run(func(tr *sqlx.Tx) error {
		var err error
		playersb, err = s.tree.Eng().LookupPlayers(ctx, tr, ids)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for i, id := range ids {
		if playersb[i] != nil {
			players[i], err = DeserializeUserSigchainPlayer(playersb[i])
			if err != nil {
				return nil, err
			}
		} else {
			players[i] = NewUserSigchainPlayer(id)
		}
	}
	return players, nil
}

func (s *Server) setPlayers(ctx logger.ContextInterface, ids [][]byte, players []*UserSigchainPlayer) error {
	var playerbs [][]byte
	for _, player := range players {
		playerb, err := player.Serialize()
		if err != nil {
			return err
		}
		playerbs = append(playerbs, playerb)
	}
	err := s.run(func(tr *sqlx.Tx) error {
		err := s.tree.Eng().StorePlayers(ctx, tr, ids, playerbs)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

var once sync.Once

func RunServer(ctx logger.ContextInterface) (*rpc.Client, error) {
	treeId := make([]byte, 16)
	_, err := cryptorand.Read(treeId)
	if err != nil {
		return nil, err
	}

	s, err := NewServerWithPostgres(ctx, treeId)
	if err != nil {
		return nil, err
	}

	err = s.Bootstrap(ctx, 0, true)
	if err != nil {
		return nil, err
	}

	once.Do(func() {
		rpc.Register(s)
		rpc.HandleHTTP()
	})
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	go http.Serve(listener, nil)
	time.Sleep(10 * time.Millisecond)

	client, err := rpc.DialHTTP("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	return client, nil
}
