package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/mvkdcrypto/mvkd/demo/logger"
	"github.com/mvkdcrypto/mvkd/demo/sigchain"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
)

type remote struct {
	address string
	name    string
	cli     *rpc.Client
}

type remotesflag struct {
	xs []remote
}

func (s *remotesflag) String() string {
	return fmt.Sprintf("%#v", s.xs)
}

func (s *remotesflag) Set(value string) error {
	tokens := strings.Split(value, ",")
	s.xs = append(s.xs, remote{name: tokens[0], address: tokens[1]})
	return nil
}

func toMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

func mainInner() error {
	var remotes remotesflag
	flag.Var(&remotes, "remote", "remote in form name;address")
	nLinksPtr := flag.Int("init", 0, "number of links to initialize")
	fakePtr := flag.Bool("fake", true, "init with fake links")
	expPtr := flag.String("exp", "", "build, query, rotate")
	cpuProfilePtr := flag.String("cpuprofile", "", "cpu profile file")
	flag.Parse()

	if *cpuProfilePtr != "" {
		f, err := os.Create(*cpuProfilePtr)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	ctx := logger.NewContext(context.TODO(), logger.NewNull())

	if len(remotes.xs) == 0 {
		return fmt.Errorf("need remote (name;address) or 'adhoc'")
	}

	for i := range remotes.xs {
		if remotes.xs[i].address == "adhoc" {
			cli, err := sigchain.RunServer(ctx)
			if err != nil {
				return err
			}
			remotes.xs[i].cli = cli
		} else {
			cli, err := rpc.DialHTTP("tcp", remotes.xs[i].address)
			if err != nil {
				return err
			}
			remotes.xs[i].cli = cli
		}
	}

	if *nLinksPtr > 0 {
		for _, remote := range remotes.xs {
			st := time.Now()
			fmt.Printf("Experiment: +Initialize(%s)\n", remote.name)
			err := sigchain.Initialize(ctx, remote.cli, *nLinksPtr, *fakePtr)
			if err != nil {
				return err
			}
			el := time.Since(st)
			fmt.Printf("Experiment: -Initialize(%s)\n", remote.name)
			fmt.Printf("Total: %v\n", el)
		}
	}

	switch *expPtr {
	case "":
	case "build":
		tikzs := []string{
			`\addplot+[ybar] plot coordinates {`,
		}
		for _, remote := range remotes.xs {
			fmt.Printf("Experiment: +Build(%s)\n", remote.name)
			ret, err := sigchain.ExperimentBuild(ctx, remote.cli)
			if err != nil {
				return err
			}
			fmt.Printf("Experiment: -Build(%s)\n", remote.name)
			tikzs[0] = tikzs[0] + fmt.Sprintf("(%s, %f)", remote.name, toMs(ret.Verify+ret.VRF+ret.Build))
		}
		tikzs[0] = tikzs[0] + "};"
		s := fmt.Sprintf(`
%s`, tikzs[0])
		fmt.Println(s)
	case "query":
		tikzs := []string{
			`\addplot+[ybar] plot coordinates {`,
			`\addplot+[ybar] plot coordinates {`,
			`\addplot+[ybar] plot coordinates {`,
		}
		tikzsBandwidth := []string{
			`\addplot+[ybar] plot coordinates {`,
		}
		for _, remote := range remotes.xs {
			fmt.Printf("Experiment: +Query(%s)\n", remote.name)
			ret, err := sigchain.ExperimentQuery(ctx, remote.cli)
			if err != nil {
				return err
			}
			fmt.Printf("Experiment: -Query(%s)\n", remote.name)
			tikzs[0] = tikzs[0] + fmt.Sprintf("(%s, %f)", remote.name, toMs(ret.Verify))
			tikzs[1] = tikzs[1] + fmt.Sprintf("(%s, %f)", remote.name, toMs(ret.Latency))
			tikzs[2] = tikzs[2] + fmt.Sprintf("(%s, %f)", remote.name, toMs(ret.Server))
			bandwidthKiB := float64(ret.ArgBandwidth+ret.RetBandwidth) / 1024
			tikzsBandwidth[0] = tikzsBandwidth[0] + fmt.Sprintf("(%s, %f)", remote.name, bandwidthKiB)
		}
		tikzs[0] = tikzs[0] + "};"
		tikzs[1] = tikzs[1] + "};"
		tikzs[2] = tikzs[2] + "};"
		tikzsBandwidth[0] = tikzsBandwidth[0] + "};"
		s := fmt.Sprintf(`
%s
%s
%s`, tikzs[0], tikzs[1], tikzs[2])
		t := fmt.Sprintf(`
%s`, tikzsBandwidth[0])
		fmt.Println(s)
		fmt.Println()
		fmt.Println(t)
	case "rotate":
		tikzs := []string{
			`\addplot plot coordinates {`,
			`\addplot plot coordinates {`,
			`\addplot plot coordinates {`,
		}
		for _, remote := range remotes.xs {
			fmt.Printf("Experiment: +Rotate(%s)\n", remote.name)
			ret, err := sigchain.ExperimentRotate(ctx, remote.cli)
			if err != nil {
				return err
			}
			fmt.Printf("Experiment: -Rotate(%s)\n", remote.name)
			fmt.Printf("Total: %v\n", ret.Total)
			fmt.Printf("VRF: %v\n", ret.VRF)
			fmt.Printf("Build: %v\n", ret.Build)
			tikzs[0] = tikzs[0] + fmt.Sprintf("(%s, %f)", remote.name, toMs(ret.Total-ret.VRF-ret.Build))
			tikzs[1] = tikzs[1] + fmt.Sprintf("(%s, %f)", remote.name, toMs(ret.VRF))
			tikzs[2] = tikzs[2] + fmt.Sprintf("(%s, %f)", remote.name, toMs(ret.Build))
		}
		tikzs[0] = tikzs[0] + "};"
		tikzs[1] = tikzs[1] + "};"
		tikzs[2] = tikzs[2] + "};"
		s := fmt.Sprintf(`
%s
%s
%s`, tikzs[0], tikzs[1], tikzs[2])
		fmt.Println(s)
	case "throughput":
		if len(remotes.xs) > 1 {
			return fmt.Errorf("can only run throughput experiment with one remote")
		}
		remote := remotes.xs[0]
		tikzs := []string{
			`\addplot+[ybar] plot coordinates {`,
		}
		fmt.Printf("Experiment: +Throughput(%s)\n", remote.name)
		ret, err := sigchain.ExperimentThroughput(ctx, remote.cli)
		if err != nil {
			return err
		}
		fmt.Printf("Experiment: -Throughput(%s)\n", remote.name)
		for n, res := range ret.Ret {
			tikzs[0] += fmt.Sprintf("(%d,%f)", n, toMs(res.Verify+res.VRF+res.Build))
		}
		tikzs[0] = tikzs[0] + "};"
		s := fmt.Sprintf(`
%s`, tikzs[0])
		fmt.Println(s)
	default:
		return fmt.Errorf("unknown command %s", *expPtr)
	}
	flag.Parse()

	return nil
}

func main() {
	err := mainInner()
	if err != nil {
		panic(errors.Wrap(err, "wrap").Error())
	}
}
