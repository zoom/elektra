package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/rpc"

	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/sigchain"

	_ "net/http/pprof"

	_ "github.com/lib/pq"
)

func mainInner() error {
	treeIdPtr := flag.String("treeId", "testtree", "tree id")
	portPtr := flag.Int("port", 3030, "port")
	flag.Parse()

	ctx := logger.NewContext(context.TODO(), logger.NewNull())
	s, err := sigchain.NewServerWithPostgres(ctx, []byte(*treeIdPtr))
	if err != nil {
		return err
	}

	rpc.Register(s)
	rpc.HandleHTTP()

	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *portPtr))
	if err != nil {
		return err
	}

	fmt.Println("Starting server...")
	http.Serve(listener, nil)
	return nil
}

func main() {
	err := mainInner()
	if err != nil {
		panic(err.Error())
	}
}
