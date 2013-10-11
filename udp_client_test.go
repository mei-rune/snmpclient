package snmpclient

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUdpClientTimeout(t *testing.T) {
	var cl Client
	var e error

	in, err := net.ListenPacket("udp", ":8324")
	if nil != err {
		t.Errorf("listenAt ':8324' failed - %s", e.Error())
		return
	}
	defer in.Close()

	cl, e = NewSnmpClient("127.0.0.1:8324")
	if nil != e {
		t.Errorf("create snmp client failed - %s", e.Error())
		return
	}

	client := cl.(*UdpClient)
	defer client.Close()

	pdu, e := client.CreatePDU(SNMP_PDU_GET, SNMP_V1)
	if nil != e {
		t.Errorf("create pdu failed - %s", e.Error())
		return
	}

	client.lastAt = time.Time{}

	res, e := client.SendAndRecv(pdu, 2*time.Second)
	if nil != e {
		t.Logf("sendAndRecv pdu failed - %s", e.Error())
	}

	if nil == res {
		t.Logf("sendAndRecv pdu failed - res is nil")
	}

	if client.lastAt.Add(2 * time.Second).After(time.Now()) {
		t.Errorf("lastAt failed - expected is %s, actual is %s", time.Now().String(), client.lastAt.String())
		return
	}

	if client.IsExpired() {
		t.Errorf("test is exprired")
		return
	}

	client.lastAt = client.lastAt.Add(time.Duration(-1**deadTimeout*2) * time.Minute)

	client.fireTick()
	if !client.IsExpired() {
		t.Errorf("test timeout failed - expected return timeout - %s", client.lastAt.String())
		return
	}

}

func startServer(laddr, pdu_txt string) (net.PacketConn, net.Addr, *sync.WaitGroup, error) {
	in, e := net.ListenPacket("udp", laddr)
	if nil != e {
		return nil, nil, nil, e
	}

	var waiter sync.WaitGroup
	waiter.Add(1)

	go serveTestUdp(in, pdu_txt, &waiter)

	return in, in.LocalAddr(), &waiter, nil
}

func stopServer(in net.PacketConn) {
	in.Close()
}

func serveTestUdp(in net.PacketConn, pdu_txt string, waiter *sync.WaitGroup) {

	defer func() {
		waiter.Done()
	}()

	var bytes [10000]byte

	for {
		_, addr, err := in.ReadFrom(bytes[:])
		if nil != err {
			fmt.Println("[test] read failed", err.Error())
			break
		}

		fmt.Println("[test] recv ok, send at next step")

		bin, err := hex.DecodeString(pdu_txt)
		if nil != err {
			fmt.Println("[test]", err.Error())
		} else {
			if _, err = in.WriteTo(bin, addr); nil != err {
				fmt.Println("[test] write failed", err.Error())
				break
			}
		}
	}
}

type callback func(t *testing.T, cl Client, laddr net.Addr)

func TestV2ReturnPdu(t *testing.T) {
	testWith(t, "127.0.0.1:0", "", snmpv1_txt, func(t *testing.T, cl Client, laddr net.Addr) {

		cl.(*UdpClient).next_id = 233
		pdu, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V1)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}

		res, err := cl.SendAndRecv(pdu, 12*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if nil == res {
			t.Errorf("sendAndRecv pdu failed - res is nil")
		}

		fmt.Println("test is end")
		//cl.FreePDU(pdu, res)
	})
}

func TestV2ReturnNoSuchInstancePdu(t *testing.T) {
	testWith(t, "127.0.0.1:0", "", snmpv2c_NOSUCHINSTANCE, func(t *testing.T, cl Client, laddr net.Addr) {

		pdu, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V1)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}

		res, err := cl.SendAndRecv(pdu, 2*time.Second)
		if nil == err {
			t.Errorf("sendAndRecv pdu failed - err is nil")
			return
		}

		if nil == res {
			t.Errorf("sendAndRecv pdu failed - res is nil")
			return
		}

		if !res.GetVariableBindings().Get(0).Value.IsError() {
			t.Errorf("sendAndRecv pdu failed - res is not error")
		}

		if SNMP_SYNTAX_NOSUCHINSTANCE != res.GetVariableBindings().Get(0).Value.GetSyntax() {
			t.Errorf("sendAndRecv pdu failed - res is not NOSUCHINSTANCE")
		}
		//cl.FreePDU(pdu, res)
	})
}

func TestV2SendFailed(t *testing.T) {
	testWith(t, "0.0.0.0:0", "33.0.0.0:0", snmpv1_txt, func(t *testing.T, cl Client, laddr net.Addr) {

		cl.(*UdpClient).next_id = 233
		pdu, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V1)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}

		_, err = cl.SendAndRecv(pdu, 2*time.Second)
		if nil == err {
			t.Errorf("except throw an error, actual return ok")
			return
		}

		if !strings.Contains(err.Error(), "time out") &&
			!strings.Contains(err.Error(), "unreachable host") {
			t.Errorf("except throw an timeout error, actual return %s", err.Error())
			return
		}
		//cl.FreePDU(pdu)
	})
}

func TestV2RecvTimeout(t *testing.T) {
	testWith(t, "127.0.0.1:0", "", snmpv1_txt, func(t *testing.T, cl Client, laddr net.Addr) {
		pdu, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V1)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}

		_, err = cl.SendAndRecv(pdu, 2*time.Second)
		if nil == err {
			t.Errorf("except throw an error, actual return ok")
			return
		}

		if !strings.Contains(err.Error(), "time out") {
			t.Errorf("except throw an timeout error, actual return %s", err.Error())
			return
		}
		//cl.FreePDU(pdu)
	})
}

func testWith(t *testing.T, laddr, caddr, pdu_txt string, f callback) {
	var waiter *sync.WaitGroup
	var listener net.PacketConn
	var cl Client

	defer func() {
		if nil != listener {
			stopServer(listener)
			waiter.Wait()
		}
	}()

	listener, addr, waiter, err := startServer(laddr, pdu_txt)
	if nil != err {
		t.Errorf("start udp server failed - %s", err.Error())
		return
	}

	if "" == caddr {
		caddr = addr.String()
	}
	cl, e := NewSnmpClient(caddr)
	if nil != e {
		t.Errorf("create snmp client failed - %s", e.Error())
		return
	}

	client := cl.(*UdpClient)
	defer client.Close()

	f(t, cl, addr)

}

// GETBULK SNMPv2c 'public' request_id=1 error_status=0 error_index=1
//  [0]: 1.3.6.1.2.1.1.4.0=NULL
//  [1]: 1.3.6.1.2.1.1.5.0=NULL
// snmp - send success, getbulk variableBindings[1.3.6.1.2.1.1.4.0=''1.3.6.1.2.1.1.5.0=''] from 127.0.0.1:161 with communit
// y = 'public' and requestId='1' and version='v2c' and max_repetitions='0' and non_repeaters='0'
// 303402010104067075626c6963a527020101020100020101301c300c06082b060102010104000500300c06082b060102010105000500
// snmp - read ok
// 303d02010104067075626c6963a2300201010201000201003025301206082b0601020101050004066d65692d7063300f06082b060102010106000403616161
// RESPONSE SNMPv2c 'public' request_id=1 error_status=0 error_index=0
//  [0]: 1.3.6.1.2.1.1.5.0=OCTET STRING 6: 6d 65 69 2d 70 63
//  [1]: 1.3.6.1.2.1.1.6.0=OCTET STRING 3: 61 61 61
// [snmp] - recv pdu success, response variableBindings[1.3.6.1.2.1.1.5.0='6d65692d7063'1.3.6.1.2.1.1.6.0='616161'] from  w
// ith community = 'public' and requestId='1' and version='v2c'
var get_bulk_request_pdu = `303402010104067075626c6963a527020101020100020101301c300c06082b060102010104000500300c06082b060102010105000500`
var get_bulk_response_pdu = `303d02010104067075626c6963a2300201010201000201003025301206082b0601020101050004066d65692d7063300f06082b060102010106000403616161`

func TestV2PduGetBulk(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		var trapError SnmpError
		var res, req PDU
		var err error

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			switch count {
			case 1:
				if get_bulk_request_pdu != hex.EncodeToString(bytes) {
					trapError = Error(SNMP_CODE_FAILED, "request is error.")
				}
				svr.ReturnWith(get_bulk_response_pdu)
			default:
				trapError = Error(SNMP_CODE_FAILED, "count is not 1.")
			}
		})

		req, err = cl.CreatePDU(SNMP_PDU_GETBULK, SNMP_V2C)
		if nil != err {
			fmt.Printf("create pdu failed - %s\r\n", err.Error())
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.community": "public"})
		req.GetVariableBindings().AppendWith(SnmpOid{1, 3, 6, 1, 2, 1, 1, 4, 0}, nil)
		req.GetVariableBindings().AppendWith(SnmpOid{1, 3, 6, 1, 2, 1, 1, 5, 0}, nil)

		res, err = cl.SendAndRecv(req, 10*time.Second)
		if nil != err {
			fmt.Printf("sendAndRecv pdu failed - %s\r\n", err.Error())
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		for _, oid1 := range []string{"1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.6.0"} {
			found := false
			for _, oid2 := range res.GetVariableBindings().All() {
				if oid1 == oid2.Oid.GetString() {
					found = true
				}
			}
			if !found {
				t.Errorf("excepted oid is", oid1, "actual is ", res.GetVariableBindings().All())
			}
		}
	})
}
