package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type options struct {
	mode         string
	targets      []string
	resolverIP   string
	rate         int
	protocol     string
	port         int
	isSilent     bool
	outputFormat string
}

var opts options

var result []string

func init() {
	flag.Usage = func() {
		h := []string{
			"Do DNS resolution(or reverse resolution) on hosts/IPs provided on stdin",
			"",
			"Usage: cat domains.txt | dns-zsolver [-m <mode>] [-R <resolver_ip>] [-r <rate>] [-c ] [-pt <protocol>] [-p <port>] [-s] [-oD]",
			"",
			"Options:",
			"  -m, --mode <fr/rr>           Resolving mode. Valid values: fr(default): Forward resolution; rr: Reverse resolution",
			"  -R, --resolver <ip>          IP address of a resolver; If omitted, will look for resolvers.txt in the current workspace",
			"  -r, --rate <num>             Rate limit(reqs/s) for each resolver. Default: 100 (reqs/s)",
			"  -P, --protocol <udp/tcp>     Protocol to use for DNS lookups. Valid values: udp(default), tcp",
			"  -p, --port <num>             Port to bother the specified DNS resolver on (default: 53)",
			"  -s, --silent                 Whether or not supress the errors",
			"  -oF, --output-format <a/s>   Output format. Valid values: a(default): Print out compelete resolved records; s: Only print out resolved IPs(or hosts in reverse mode)",
			"",
		}

		fmt.Fprint(os.Stderr, strings.Join(h, "\n"))
	}
}

func main() {
	var mode string
	flag.StringVar(&mode, "mode", "fr", "")
	flag.StringVar(&mode, "m", "fr", "")

	var resolverIP string
	flag.StringVar(&resolverIP, "resolver", "", "")
	flag.StringVar(&resolverIP, "R", "", "")

	var rate int
	flag.IntVar(&rate, "rate", 100, "")
	flag.IntVar(&rate, "r", 100, "")

	var protocol string
	flag.StringVar(&protocol, "protocol", "udp", "")
	flag.StringVar(&protocol, "P", "udp", "")

	var port int
	flag.IntVar(&port, "port", 53, "")
	flag.IntVar(&port, "p", 53, "")

	var isSilent bool
	flag.BoolVar(&isSilent, "silent", false, "")
	flag.BoolVar(&isSilent, "s", false, "")

	var outputFormat string
	flag.StringVar(&outputFormat, "oF", "a", "")
	flag.StringVar(&outputFormat, "output-format", "a", "")

	flag.Parse()

	opts = options{mode: mode, resolverIP: resolverIP, rate: rate, protocol: protocol, port: port, isSilent: isSilent, outputFormat: outputFormat}

	err := preCheck()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return
	}

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		opts.targets = append(opts.targets, strings.TrimSpace(sc.Text()))
	}

	if len(opts.targets) > 0 {
		createResolverPool()

		for _, v := range result {
			fmt.Println(v)
		}
	}
}

func preCheck() (err error) {
	if len(opts.mode) == 0 {
		return fmt.Errorf("mode is unset")
	}

	if opts.mode != "fr" && opts.mode != "rr" {
		return fmt.Errorf("mode is invalid")
	}

	if len(opts.outputFormat) > 0 && opts.outputFormat != "a" && opts.outputFormat != "s" {
		return fmt.Errorf("output format is invalid")
	}

	return nil
}

func createResolverPool() {
	resolvers, err := getResolvers()
	if err != nil {
		if !opts.isSilent {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
		}
		return
	}

	var wg sync.WaitGroup
	for _, resolver := range resolvers {
		wg.Add(1)
		go resolve(resolver, &wg)
	}
	wg.Wait()
}

func getResolvers() ([]string, error) {
	var resolvers []string
	if len(opts.resolverIP) > 0 {
		resolvers = append(resolvers, opts.resolverIP)
	} else {
		pwd, err := filepath.Abs(".")
		if err != nil {
			return nil, fmt.Errorf("unable to set workspace to %s : %s", pwd, err)
		}

		rPath := filepath.Join(pwd, "resolvers.txt")
		f, err := os.Open(rPath)
		if err != nil {
			return nil, fmt.Errorf("unable to load resolvers : %s", err)
		}

		scanner := bufio.NewScanner(f)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			resolvers = append(resolvers, scanner.Text())
		}

		f.Close()
	}

	return resolvers, nil
}

func resolve(resolver string, wg *sync.WaitGroup) {
	defer wg.Done()

	jobs := make(chan string, 2)

	go allocateJobs(jobs)

	createWorkerPool(resolver, jobs)
}

func allocateJobs(jobs chan string) {
	for _, target := range opts.targets {
		jobs <- target
	}
	close(jobs)
}

func createWorkerPool(resolver string, jobs chan string) {
	var wg sync.WaitGroup
	for i := 0; i < opts.rate; i++ {
		wg.Add(1)
		go doJobs(resolver, i, jobs, &wg)
	}
	wg.Wait()
}

func doJobs(resolver string, id int, jobs chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		//fmt.Printf("resolver: %s, worker: %d, target: %s\n", resolver, id, job)
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Second * time.Duration(10)}
				return d.DialContext(ctx, opts.protocol, fmt.Sprintf("%s:%d", resolver, opts.port))
			},
		}

		if opts.mode == "fr" {
			cname, err := r.LookupCNAME(context.Background(), job)
			if err != nil {
				if !opts.isSilent {
					fmt.Fprintf(os.Stderr, "error resolving %s on %s : %s\n", job, resolver, err)
				}

				continue
			}

			if job+"." != cname {
				appendToResult(fmt.Sprintf("%s CNAME %s", job, cname))
			} else {
				addrs, err := r.LookupHost(context.Background(), job)
				if err != nil {
					if !opts.isSilent {
						fmt.Fprintf(os.Stderr, "error resolving %s on %s : %s\n", job, resolver, err)
					}

					continue
				}

				for _, a := range addrs {
					appendToResult(fmt.Sprintf("%s A %s", job, a))
				}

			}
		} else if opts.mode == "rr" {
			hosts, err := r.LookupAddr(context.Background(), job)
			if err != nil {
				if !opts.isSilent {
					fmt.Fprintf(os.Stderr, "error resolving %s on %s : %s\n", job, resolver, err)
				}

				continue
			}

			for _, h := range hosts {
				appendToResult(fmt.Sprintf("%s PTR %s", job, h))
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func appendToResult(s string) {
	for _, v := range result {
		if v == s {
			return
		}
	}

	result = append(result, s)
}
