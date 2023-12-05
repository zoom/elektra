package sigchain

import (
	"fmt"
	"net"
	"net/http"
	"net/rpc"
	"sync"
	"time"

	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/merkle"
	"github.com/mvkdcrypto/mvkd/demo/storage"
	"github.com/jmoiron/sqlx"
)

type Auditor struct {
	cfg  merkle.Config
	tree *merkle.Tree
}

func (a *Auditor) run(f func(tr *sqlx.Tx) error) error {
	switch eng := a.tree.Eng().(type) {
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
	default:
		return f(nil)
	}
}

func NewAuditor(ctx logger.ContextInterface, eng merkle.StorageEngine) (*Auditor, error) {
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
	s := &Auditor{
		cfg:  cfg,
		tree: tree,
	}
	return s, nil
}

func NewAuditorWithPostgres(ctx logger.ContextInterface, treeId []byte) (*Auditor, error) {
	cfg, err := NewConfig()
	if err != nil {
		return nil, err
	}
	auditorPrefix := []byte("aud-")
	eng, err := newPostgresEngine(cfg, append(auditorPrefix, treeId...))
	if err != nil {
		return nil, err
	}
	s, err := NewAuditor(ctx, eng)
	if err != nil {
		return nil, err
	}
	return s, nil
}

var auditorOnce sync.Once

func RunAuditor(ctx logger.ContextInterface, treeId []byte) (*rpc.Client, error) {
	s, err := NewAuditorWithPostgres(ctx, treeId)
	if err != nil {
		return nil, err
	}

	auditorOnce.Do(func() {
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
