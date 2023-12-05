package sigchain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/rpc"
	"time"

	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/merkle"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

func Initialize(ctx logger.ContextInterface, client *rpc.Client, nLinks int, fake bool) error {
	arg := InitializeArg{NLinks: nLinks, Fake: fake}
	ret := InitializeRet{}
	err := client.Call("Server.Initialize", arg, &ret)
	if err != nil {
		return err
	}

	return nil
}

type ExperimentBuildResult struct {
	Total  time.Duration
	Verify time.Duration
	VRF    time.Duration
	Build  time.Duration
}

func ExperimentBuild(ctx logger.ContextInterface, client *rpc.Client) (ExperimentBuildResult, error) {
	nInitUsers := 10
	var devices []*Device
	for i := 0; i < nInitUsers; i++ {
		device, err := NewDevice(client, []byte(fmt.Sprintf("user%d", i)))
		if err != nil {
			return ExperimentBuildResult{}, err
		}
		err = device.UpdateMe(ctx)
		if err != nil {
			return ExperimentBuildResult{}, err
		}
		link, err := device.AddFirstKey()
		if err != nil {
			return ExperimentBuildResult{}, err
		}
		_, err = device.BuildEpoch(ctx, []Link{link})
		if err != nil {
			return ExperimentBuildResult{}, err
		}
		devices = append(devices, device)
	}

	var newLinks []Link
	for _, device := range devices {
		link, err := makeNewLink(ctx, device)
		if err != nil {
			return ExperimentBuildResult{}, err
		}
		newLinks = append(newLinks, link)
	}
	buildEpochRet, err := devices[0].BuildEpoch(ctx, newLinks)
	if err != nil {
		return ExperimentBuildResult{}, err
	}
	res := ExperimentBuildResult{
		Total:  buildEpochRet.Total,
		Verify: buildEpochRet.Verify,
		VRF:    buildEpochRet.VRF,
		Build:  buildEpochRet.Build,
	}

	return res, nil
}

func makeNewLink(ctx logger.ContextInterface, device *Device) (Link, error) {
	err := device.UpdateMe(ctx)
	if err != nil {
		return Link{}, err
	}
	link, err := device.Extra([]byte("extra"))
	if err != nil {
		return Link{}, err
	}
	return link, nil
}

// in ms
type ExperimentQueryResult struct {
	Total        time.Duration
	Latency      time.Duration
	Server       time.Duration
	Verify       time.Duration
	ArgBandwidth int
	RetBandwidth int
}

func ExperimentQuery(ctx logger.ContextInterface, client *rpc.Client) (res ExperimentQueryResult, err error) {
	userId, err := merkle.RandomBytes(16)
	if err != nil {
		return res, err
	}

	device, err := NewDevice(client, userId)
	if err != nil {
		return res, err
	}

	userIds, err := setupQueryExperiment(ctx, client)
	if err != nil {
		return res, err
	}

	err = device.UpdateClock(ctx)
	if err != nil {
		return res, err
	}

	stbuffer := time.Now()
	_, err = device.BuildEpochs(ctx, 300)
	if err != nil {
		return res, err
	}
	elbuffer := time.Since(stbuffer)
	fmt.Println("Query setup: created epoch buffer in", elbuffer)

	start := time.Now()
	networkTime, verifyTime, serverTime, argBandwidth, retBandwidth, err := device.UpdateBench(ctx, userIds)
	if err != nil {
		return res, err
	}
	elapsed := time.Since(start)

	// sanity check
	for _, userId := range userIds {
		pl := device.Player(userId)
		if pl.Sigchain.Len() != 10 {
			return res, fmt.Errorf("bad len in received sigchain")
		}
	}

	return ExperimentQueryResult{
		Total:        elapsed,
		Verify:       verifyTime,
		Latency:      networkTime - serverTime,
		Server:       serverTime,
		ArgBandwidth: argBandwidth,
		RetBandwidth: retBandwidth,
	}, nil
}

func setupQueryExperiment(ctx logger.ContextInterface, s *rpc.Client) ([][]byte, error) {
	var userIds [][]byte

	n := 10

	st := time.Now()
	var links []Link
	var devices []*Device
	var device2s []*Device
	for i := 0; i < n; i++ {
		userId := append([]byte("YELLOW_SUBMARINE"), byte(i))
		userIds = append(userIds, userId)
	}

	for i := 0; i < n; i++ {
		userId := userIds[i]
		device, err := NewDevice(s, userId)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)

		err = device.UpdateMe(ctx)
		if err != nil {
			return nil, err
		}
		if device.Me().Sigchain.Len() > 0 {
			// already set up
			return userIds, nil
		}

		link, err := device.AddFirstKey()
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}

	_, err := devices[0].BuildEpoch(ctx, links)
	if err != nil {
		return nil, err
	}

	links = nil

	for i := 0; i < n; i++ {
		device := devices[i]
		userId := userIds[i]
		device2, err := NewDevice(s, userId)
		if err != nil {
			return nil, err
		}
		device2s = append(device2s, device2)

		err = device.UpdateMe(ctx)
		if err != nil {
			return nil, err
		}

		link, err := device.AddKey(device2)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	_, err = devices[0].BuildEpoch(ctx, links)
	if err != nil {
		return nil, err
	}

	links = nil

	for i := 0; i < n; i++ {
		device := devices[i]
		device2 := device2s[i]
		err = device.UpdateMe(ctx)
		if err != nil {
			return nil, err
		}

		link, err := device.Revoke(device2.PublicKey())
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	_, err = devices[0].BuildEpoch(ctx, links)
	if err != nil {
		return nil, err
	}

	for j := 0; j < 7; j++ {
		links = nil
		for i := 0; i < n; i++ {
			device := devices[i]
			err := device.UpdateMe(ctx)
			if err != nil {
				return nil, err
			}
			link, err := device.Extra([]byte("YELLOW_SUBMARINE"))
			if err != nil {
				return nil, err
			}
			links = append(links, link)
		}

		_, err = devices[0].BuildEpoch(ctx, links)
		if err != nil {
			return nil, err
		}

	}
	el := time.Since(st)
	fmt.Println("Query setup: created users in", el)

	return userIds, nil
}

type ExperimentRotateResult struct {
	Total time.Duration
	VRF   time.Duration
	Build time.Duration
}

func ExperimentRotate(ctx logger.ContextInterface, client *rpc.Client) (res ExperimentRotateResult, err error) {
	arg := RotateArg{}
	ret := RotateRet{}
	err = client.Call("Server.Rotate", arg, &ret)
	if err != nil {
		return res, errors.Wrap(err, "err")
	}

	res.Total = ret.Total
	res.VRF = ret.VRF
	res.Build = ret.Build

	return res, nil
}

type ExperimentThroughputResult struct {
	Ret map[int]ExperimentBuildResult
}

func ExperimentThroughput(ctx logger.ContextInterface, client *rpc.Client) (res ExperimentThroughputResult, err error) {
	res.Ret = make(map[int]ExperimentBuildResult)
	ns := []int{32, 64, 128, 256, 512, 1024}
	err = throughputSetup(ctx, client, ns[len(ns)-1])
	if err != nil {
		return res, err
	}
	for _, n := range ns {
		fmt.Printf("Experiment: Throughput[%d]\n", n)
		ret, err := throughputTrial(ctx, client, n)
		if err != nil {
			return res, err
		}
		res.Ret[n] = ret
	}
	return res, nil
}

func throughputSetup(ctx logger.ContextInterface, client *rpc.Client, n int) error {
	var preLinks []Link
	var mydevice *Device
	st := time.Now()
	for i := 0; i < n; i++ {
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.BigEndian, uint64(i))
		if err != nil {
			return err
		}
		userId := append([]byte("THROUGHPUTSUB"), buf.Bytes()...)

		device, err := NewDeterministicDeviceDanger(client, userId)
		if err != nil {
			return err
		}
		mydevice = device

		err = device.UpdateMe(ctx)
		if err != nil {
			return err
		}

		if device.Me().Sigchain.Len() > 0 {
			// already set up
			return nil
		}

		link, err := device.AddFirstKey()
		if err != nil {
			return err
		}

		preLinks = append(preLinks, link)
	}
	if len(preLinks) == 0 {
		return nil
	}
	_, err := mydevice.BuildEpoch(ctx, preLinks)
	if err != nil {
		return err
	}
	el := time.Since(st)
	fmt.Println("Throughput setup: created users in", el)
	return nil
}

func throughputTrial(ctx logger.ContextInterface, client *rpc.Client, n int) (res ExperimentBuildResult, err error) {
	newLinks := make([]Link, n)
	var mydevice *Device
	g := new(errgroup.Group)
	g.SetLimit(90) // pq default connection limit is 100
	for i := 0; i < n; i++ {
		i := i
		g.Go(func() error {
			buf := new(bytes.Buffer)
			err := binary.Write(buf, binary.BigEndian, uint64(i))
			if err != nil {
				return err
			}
			userId := append([]byte("THROUGHPUTSUB"), buf.Bytes()...)

			device, err := NewDeterministicDeviceDanger(client, userId)
			if err != nil {
				return err
			}
			mydevice = device

			link, err := makeNewLink(ctx, device)
			if err != nil {
				return err
			}
			newLinks[i] = link
			return nil
		})
	}
	err = g.Wait()
	if err != nil {
		return ExperimentBuildResult{}, err
	}
	buildEpochRet, err := mydevice.BuildEpoch(ctx, newLinks)
	if err != nil {
		return ExperimentBuildResult{}, err
	}
	res = ExperimentBuildResult{
		Total:  buildEpochRet.Total,
		Verify: buildEpochRet.Verify,
		VRF:    buildEpochRet.VRF,
		Build:  buildEpochRet.Build,
	}

	return res, nil
}
