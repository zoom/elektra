package main

import (
	"flag"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func mainInner() error {
	dbPtr := flag.String("db", "", "leveldb file")
	flag.Parse()

	if *dbPtr == "" {
		return fmt.Errorf("need --db")
	}

	leveldb, err := leveldb.OpenFile(*dbPtr, nil)
	if err != nil {
		return err
	}

	err = leveldb.CompactRange(util.Range{})
	if err != nil {
		return err
	}

	return nil
}

func main() {
	err := mainInner()
	if err != nil {
		panic(err.Error())
	}
}
