package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	. "github.com/runner-mei/snmpclient"
)

var (
	community   = flag.String("community", "", "set the community string")
	version     = flag.String("version", "v1", "specifies SNMP version to use")
	request_id  = flag.String("request_id", "", "specifies request id to use")
	timeout     = flag.Duration("timeout", 10*time.Second, "set the request timeout")
	listen_mode = flag.Bool("listen_mode", false, "use listen mode.")
)

func main() {
	var cl Client
	var e error

	flag.Parse()
	if 2 != len(flag.Args()) {
		fmt.Println("Usage:", os.Args[0], "[options] host_address oid")
		flag.PrintDefaults()
		fmt.Println("Examples:\r\n ", os.Args[0], "-community=public 127.0.0.1:161 1.3.6.1.2.1.1.1.0")
		return
	}
	address := flag.Args()[0]
	oid_str := flag.Args()[1]

	cl, e = NewSnmpClientWith(address,
		1*time.Second,
		time.Duration(3)*time.Minute,
		&LogWriter{}, &LogWriter{})
	//cl, e = NewSnmpClient("172.16.180.10:161")
	if nil != e {
		fmt.Printf("create snmp client failed - %s", e.Error())
		return
	}
	defer cl.Close()

	if *listen_mode {
		cl.(*UdpClient).UseListenMode()
	}

	ver, e := ParseSnmpVersion(*version)
	if nil != e {
		fmt.Println(e)
		return
	}

	if "" != *request_id {
		i64, e := strconv.ParseInt(*request_id, 10, 32)
		if nil != e {
			fmt.Println("")
			return
		}
		cl.(*UdpClient).SetNextId(int32(i64))
	}

	pdu, e := cl.CreatePDU(SNMP_PDU_GET, ver)
	if nil != e {
		fmt.Printf("create pdu failed - %s", e.Error())
		return
	}
	if e = pdu.Init(map[string]string{"snmp.community": *community}); nil != e {
		fmt.Printf("create pdu failed - %s", e.Error())
		return
	}
	if e = pdu.GetVariableBindings().Append(oid_str, ""); nil != e {
		fmt.Printf("create pdu failed - %s", e.Error())
		return
	}
	res, e := cl.SendAndRecv(pdu, *timeout)
	if nil != e {
		fmt.Printf("sendAndRecv pdu failed - %s", e.Error())
		return
	}

	if nil == res {
		fmt.Printf("sendAndRecv pdu failed - res is nil")
		return
	}
	fmt.Println(res)
}
