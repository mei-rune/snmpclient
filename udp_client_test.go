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

	cl, e = NewSnmpClient("127.0.0.1:161")
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

	client.lastActive = time.Time{}

	res, e := client.SendAndRecv(pdu, 2*time.Second)
	if nil != e {
		t.Logf("sendAndRecv pdu failed - %s", e.Error())
	}

	if nil == res {
		t.Logf("sendAndRecv pdu failed - res is nil")
	}

	if client.lastActive.Add(2 * time.Second).After(time.Now()) {
		t.Errorf("lastActive failed - expected is %s, actual is %s", time.Now().String(), client.lastActive.String())
		return
	}

	e = client.Test()
	if nil != e {
		t.Errorf("test timeout failed - %s", e.Error())
		return
	}

	client.lastActive = client.lastActive.Add(time.Duration(-1**deadTimeout*2) * time.Minute)

	e = client.Test()
	if nil == e {
		t.Errorf("test timeout failed - expected return timeout - %s", client.lastActive.String())
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
			fmt.Println(err.Error())
			break
		}

		bin, err := hex.DecodeString(pdu_txt)
		if nil != err {
			fmt.Println(err.Error())
		} else {
			in.WriteTo(bin, addr)
		}
	}
}

type callback func(t *testing.T, cl Client, laddr net.Addr)

func TestReturnPdu(t *testing.T) {
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

		//cl.FreePDU(pdu, res)
	})
}

func TestReturnNoSuchInstancePdu(t *testing.T) {
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

func TestSendFailed(t *testing.T) {
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

func TestRecvTimeout(t *testing.T) {
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
