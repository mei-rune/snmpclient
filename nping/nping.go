package main

import (
	"flag"
	"fmt"
	"net"
	"snmpclient"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	//"web"
)

var (
	laddr       = flag.String("laddr", "0.0.0.0:0", "the address of bind, default: '0.0.0.0:0'")
	network     = flag.String("network", "udp4", "the family of address, default: 'udp4'")
	timeout     = flag.Int("timeout", 5, "the family of address, default: '5'")
	port        = flag.String("port", "161", "the port of address, default: '161'")
	communities = flag.String("communities", "public;public1", "the community of snmp")
)

func main() {
	flag.Parse()

	targets := flag.Args()
	if nil == targets || 1 != len(targets) {
		flag.Usage()
		return
	}

	scanner := snmpclient.NewPingers(256)

	for _, community := range strings.Split(*communities, ";") {
		e := scanner.Listen(*network, *laddr, snmpclient.SNMP_V2C, community)
		if nil != e {
			fmt.Println(e)
			return
		}
	}

	defer scanner.Close()

	ip_range, err := ParseIPRange(targets[0])
	if nil != err {
		fmt.Println(err)
		return
	}
	var wait sync.WaitGroup
	is_stopped := int32(0)
	go func() {
		for i := 0; i < scanner.Length(); i++ {
			ip_range.Reset()

			if i != 0 {
				time.Sleep(500 * time.Millisecond)
			}

			for ip_range.HasNext() {
				err = scanner.Send(i, net.JoinHostPort(ip_range.Current().String(), *port))
				if nil != err {
					fmt.Println(err)
					goto end
				}
			}
		}
	end:
		atomic.StoreInt32(&is_stopped, 1)
		wait.Done()
	}()
	wait.Add(1)

	for {
		ra, t, err := scanner.Recv(time.Duration(*timeout) * time.Second)
		if nil != err {
			if err == snmpclient.TimeoutError {
				fmt.Println(err)
			} else if 0 == atomic.LoadInt32(&is_stopped) {
				continue
			}
			break
		}
		fmt.Println(ra, t)
	}
	wait.Wait()
}
