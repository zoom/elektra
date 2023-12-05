package main

import (
	"github.com/mvkdcrypto/mvkd/demo/sigchain"
	"github.com/mvkdcrypto/mvkd/demo/storage"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

func inner() error {
	cfg, err := sigchain.NewConfig()
	if err != nil {
		return err
	}

	// db, err := sqlx.Connect("sqlite3", "file:test.db")
	db, err := sqlx.Open("postgres", "user=foo dbname=merkle sslmode=disable")
	if err != nil {
		return err
	}

	treeId := []byte{1, 2, 3}

	eng := storage.NewMerkleStorageEngine(db, cfg, treeId)

	err = eng.Reset()
	if err != nil {
		return err
	}

	return nil
}

func main() {
	err := inner()
	if err != nil {
		panic(err)
	}
}
