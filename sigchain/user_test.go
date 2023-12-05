package sigchain

import (
	"context"
	"net/rpc"
	"testing"

	"github.com/mvkdcrypto/mvkd/demo/logger"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

var alice = []byte("Alice")

func NewCtx(t testing.TB) logger.ContextInterface {
	return logger.NewContext(context.TODO(), logger.NewTestLogger(t))
}

func setup(t testing.TB) (logger.ContextInterface, *rpc.Client) {
	ctx := NewCtx(t)

	client, err := RunServer(ctx)
	require.NoError(t, err)

	return ctx, client

	// 	treeId := make([]byte, 16)
	// 	_, err := cryptorand.Read(treeId)
	// 	require.NoError(t, err)

	// 	s, err := NewServerWithPostgres(ctx, treeId)
	// 	require.NoError(t, err)

	// 	err = s.Initialize(ctx)
	// 	require.NoError(t, err)

	// 	once.Do(func() {
	// 		rpc.Register(s)
	// 		rpc.HandleHTTP()
	// 	})

	// 	listener, err := net.Listen("tcp", ":0")
	// 	require.NoError(t, err)
	// 	port := listener.Addr().(*net.TCPAddr).Port
	// 	go http.Serve(listener, nil)
	// 	time.Sleep(10 * time.Millisecond)

	// 	client, err := rpc.DialHTTP("tcp", fmt.Sprintf(":%d", port))
	// 	require.NoError(t, err)

	// return ctx, client
}

func TestFastForward(t *testing.T) {
	ctx, s := setup(t)

	d, err := NewDevice(s, alice)
	require.NoError(t, err)

	err = d.UpdateMe(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, d.Me().Sigchain.Len())
	require.Equal(t, 1, d.clock.LastSeenEpno)

	for idx := 0; idx < 5; idx++ {
		_, err = d.BuildEpoch(ctx, nil)
		require.NoError(t, err)
	}

	err = d.UpdateMe(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, d.Me().Sigchain.Len())
	require.Equal(t, 6, d.clock.LastSeenEpno)
}

func TestAddFirstKey(t *testing.T) {
	ctx, s := setup(t)

	d, err := NewDevice(s, alice)
	require.NoError(t, err)

	err = d.UpdateMe(ctx)
	require.NoError(t, err)

	link, err := d.AddFirstKey()
	require.NoError(t, err)
	_, err = d.BuildEpoch(ctx, []Link{link})
	require.NoError(t, err)

	err = d.UpdateMe(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, len(d.Me().Sigchain))
}

func TestAddKey(t *testing.T) {
	ctx, s := setup(t)

	d1, err := NewDevice(s, alice)
	require.NoError(t, err)

	d2, err := NewDevice(s, alice)
	require.NoError(t, err)

	err = d1.UpdateMe(ctx)
	require.NoError(t, err)
	link, err := d1.AddFirstKey()
	require.NoError(t, err)
	_, err = d1.BuildEpoch(ctx, []Link{link})
	require.NoError(t, err)

	err = d1.UpdateMe(ctx)
	require.NoError(t, err)

	require.Equal(t, len(d1.Me().ActiveKeys), 1)

	link, err = d1.AddKey(d2)
	require.NoError(t, err)
	_, err = d1.BuildEpoch(ctx, []Link{link})
	require.NoError(t, err)

	err = d1.UpdateMe(ctx)
	require.NoError(t, err)

	err = d2.UpdateMe(ctx)
	require.NoError(t, err)

	require.Equal(t, len(d1.Me().ActiveKeys), 2)
	require.Equal(t, len(d2.Me().ActiveKeys), 2)
}
