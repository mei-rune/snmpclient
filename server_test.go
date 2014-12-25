package snmpclient

import (
	"encoding/hex"
	"net"
	"sync"
	"testing"
)

type trap_cb func(svr *snmpTestServer, count int, bytes []byte)
type snmpTestServer struct {
	t             *testing.T
	isFirstListen bool
	origin        string
	conn          net.PacketConn
	listenAddr    net.Addr
	waitGroup     *sync.WaitGroup

	send_pdu string
	recv_pdu string

	trapCount int
	cb        trap_cb
}

func (svr *snmpTestServer) TrapWith(cb trap_cb) {
	svr.cb = cb
}

func (svr *snmpTestServer) ReturnWith(pdu string) {
	svr.send_pdu = pdu
}

func (svr *snmpTestServer) Stop() {
	svr.conn.Close()
}

func (svr *snmpTestServer) Start() {
	var in net.PacketConn
	var e error

	if nil == svr.listenAddr {
		in, e = net.ListenPacket("udp", svr.origin)
		svr.t.Log("[test_server]", "listen at", in.LocalAddr())
	} else {
		in, e = net.ListenPacket("udp", svr.listenAddr.String())
		svr.t.Log("[test_server]", "listen at", svr.listenAddr.String())
	}
	if nil != e {
		panic(e.Error())
	}

	svr.isFirstListen = false
	svr.waitGroup.Add(1)
	svr.conn = in
	svr.listenAddr = in.LocalAddr()

	go serveTestUdp2(svr)

}

func startServer2(t *testing.T, laddr string) (*snmpTestServer, error) {

	svr := &snmpTestServer{t: t, isFirstListen: true, origin: laddr, waitGroup: &sync.WaitGroup{}}
	svr.Start()

	return svr, nil
}

func stopServer2(svr *snmpTestServer) {
	if nil != svr.conn {
		svr.conn.Close()
	}
}

func serveTestUdp2(svr *snmpTestServer) {
	defer func() {
		svr.conn = nil
		svr.waitGroup.Done()
	}()

	var bytes [10000]byte

	for {
		recv_bytes, addr, err := svr.conn.ReadFrom(bytes[:])
		if nil != err {
			svr.t.Log("[test_server]", err.Error())
			break
		}
		svr.recv_pdu = hex.EncodeToString(bytes[0:recv_bytes])
		if nil != svr.cb {
			svr.trapCount++
			svr.cb(svr, svr.trapCount, bytes[0:recv_bytes])
		}

		bin, err := hex.DecodeString(svr.send_pdu)
		if nil != err {
			svr.t.Log("[test_server]", err.Error())
		} else {
			svr.conn.WriteTo(bin, addr)
		}
	}
}

type snmpTestServer_callback func(t *testing.T, cl Client, listener *snmpTestServer)

func testSnmpWith(t *testing.T, laddr, caddr string, f snmpTestServer_callback) {
	var listener *snmpTestServer
	var cl Client

	defer func() {
		if nil != listener {
			stopServer2(listener)
			listener.waitGroup.Wait()
		}
	}()

	listener, err := startServer2(t, laddr)
	if nil != err {
		t.Errorf("start udp server failed - %s", err.Error())
		return
	}

	if "" == caddr {
		caddr = listener.listenAddr.String()
	}
	cl, e := NewSnmpClient(caddr)
	if nil != e {
		t.Errorf("create snmp client failed - %s", e.Error())
		return
	}
	client := cl.(*UdpClient)
	defer client.Close()

	f(t, cl, listener)
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// read_success_with_auto_discover
// 2012/11/16 11:37:46 snmp - invoke begin.
// 2012/11/16 11:37:46 snmp - read ok
// 2012/11/16 11:37:46 305f020103300e020101020300ffe3040100020103041c301a040a80001f880468617a656c0202010a02022c87040004000400302c040a80001f880468617a656c0400a81c0201010201000201003011300f060a2b060106030f01010400410109
// 2012/11/16 11:37:46 snmp - send success, get variableBindings[] from 127.0.0.1:161 with auth = '[noauth]' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[noauth]' and priv = '[nopriv]' and requestId='1. and identifier='1' and version='v3'
// 2012/11/16 11:37:46 snmp - send success, next variableBindings[1.3.6=''] from  with auth = '[md5]mfk123456' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[md5]mfk123456' and priv = '[nopriv]' and requestId='2. and identifier='2' and version='v3'
// 2012/11/16 11:37:46 snmp - read ok
// 2012/11/16 11:37:46 3081d3020103300e020102020300ffe3040101020103042c302a040a80001f880468617a656c0202010a02022c8704046d666b31040c40365ebe8c88f4ab6b1a2203040030818f040a80001f880468617a656c0400a27f0201020201000201003074307206082b06010201010100046657696e646f77732048617a656c20362e302e363030322053657276696365205061636b2032202053657276657220342e302c20456e74657270726973652045646974696f6e207838362046616d696c792036204d6f64656c203233205374657070696e672036
// 2012/11/16 11:37:46 snmp - recv pdu success, response variableBindings[1.3.6.1.2.1.1.1.0='57696e646f77732048617a656c20362e302e363030322053657276696365205061636b2032202053657276657220342e302c20456e74657270726973652045646974696f6e207838362046616d696c792036204d6f64656c203233205374657070696e672036'] from  with auth = '[md5]' and priv = '[nopriv]' and contextName='' and contextEngine='80001f880468617a656c and auth = '[md5]' and priv = '[nopriv]' and requestId='2. and identifier='2' and version='v3'
// 2012/11/16 11:37:46 snmp - invoke end.
// 2012/11/16 11:37:46 snmp - invoke begin.
// 2012/11/16 11:37:46 snmp - send success, next variableBindings[1.3.6.1.2.1.1.1.0=''] from  with auth = '[md5]mfk123456' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[md5]mfk123456' and priv = '[nopriv]' and requestId='3. and identifier='3' and version='v3'
// 2012/11/16 11:37:46 snmp - read ok
// 2012/11/16 11:37:46 3076020103300e020103020300ffe3040101020103042c302a040a80001f880468617a656c0202010a02022c8704046d666b31040c1accd5d5e9b5c99bd8b9b89c04003033040a80001f880468617a656c0400a2230201030201000201003018301606082b06010201010200060a2b06010401bf0803020d
// 2012/11/16 11:37:46 snmp - recv pdu success, response variableBindings[1.3.6.1.2.1.1.2.0='1.3.6.1.4.1.8072.3.2.13'] from  with auth = '[md5]' and priv = '[nopriv]' and contextName='' and contextEngine='80001f880468617a656c and auth = '[md5]' and priv = '[nopriv]' and requestId='3. and identifier='3' and version='v3'
// 2012/11/16 11:37:46 snmp - invoke end.
// 2012/11/16 11:37:46 snmp - invoke begin.
// 2012/11/16 11:37:46 snmp - send success, next variableBindings[1.3.6.1.2.1.1.2.0=''] from  with auth = '[md5]mfk123456' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[md5]mfk123456' and priv = '[nopriv]' and requestId='4. and identifier='4' and version='v3'
// 2012/11/16 11:37:46 snmp - read ok
// 2012/11/16 11:37:46 306f020103300e020104020300ffe3040101020103042c302a040a80001f880468617a656c0202010a02022c8704046d666b31040c653dde6ad603d9ce5587dd1f0400302c040a80001f880468617a656c0400a21c0201040201000201003011300f06082b060102010103004303116531
// GET SNMPv3 '' identifier: 1
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname:
//  user.auth_proto: 0
//  user.auth_key 0:
//  user.priv_proto: 0
//  user.priv_key 0:
//  engine boots=0, time=0, max_msg_size=10000, engine.engine_id:  0:
//  request_id=1 error_status=0 error_index=0
// REPORT SNMPv3 '' identifier: 1
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname:
//  user.auth_proto: 0
//  user.auth_key 0:
//  user.priv_proto: 0
//  user.priv_key 0:
//  engine boots=266, time=11399, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=1 error_status=0 error_index=0
//  [0]: 1.3.6.1.6.3.15.1.1.4.0=COUNTER 9
// GETNEXT SNMPv3 '' identifier: 2
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=11399, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=2 error_status=0 error_index=0
//  [0]: 1.3.6=NULL
// RESPONSE SNMPv3 '' identifier: 2
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: 40 36 5e be 8c 88 f4 ab 6b 1a 22 03
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=11399, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=2 error_status=0 error_index=0
//  [0]: 1.3.6.1.2.1.1.1.0=OCTET STRING 102: 57 69 6e 64 6f 77 73 20 48 61 7a 65 6c 20 36 2e 30 2e 36 30 30 32 20 53 65 72 76 69 63 65 20 50 61 63 6b 20 32 20 20 53 65 72 76 65 72 20 34 2e 30 2c 20 45 6e 74 65 72 70 72 69 73 65 20 45 64 69 74 69 6f 6e 20 78 38 36 20 46 61 6d 69 6c 79 20 36 20 4d 6f 64 65 6c 20 32 33 20 53 74 65 70 70 69 6e 67 20 36
// GETNEXT SNMPv3 '' identifier: 3
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=11399, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=3 error_status=0 error_index=0
//  [0]: 1.3.6.1.2.1.1.1.0=NULL
// RESPONSE SNMPv3 '' identifier: 3
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: 1a cc d5 d5 e9 b5 c9 9b d8 b9 b8 9c
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=11399, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=3 error_status=0 error_index=0
//  [0]: 1.3.6.1.2.1.1.2.0=OID 1.3.6.1.4.1.8072.3.2.13
// GETNEXT SNMPv3 '' identifier: 4
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=11399, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=4 error_status=0 error_index=0
//  [0]: 1.3.6.1.2.1.1.2.0=NULL
// RESPONSE SNMPv3 '' identifier: 4
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: 65 3d de 6a d6 03 d9 ce 55 87 dd 1f
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0
// 2012/11/16 11:37:46 snmp - recv pdu success, response variableBindings[1.3.6.1.2.1.1.3.0='1140017'] from  with auth = '[md5]' and priv = '[nopriv]' and contextName='' and contextEngine='80001f880468617a656c and auth = '[md5]' and priv = '[nopriv]' and requestId='4. and identifier='4' and version='v3'
const (
	discover_response_pdu = "305f020103300e020101020300ffe3040100020103041c301a040a80001f880468617a656c0202010a02022c87040004000400302c040a80001f880468617a656c0400a81c0201010201000201003011300f060a2b060106030f01010400410109"
	read_v3_response_pdu  = "3081d3020103300e020102020300ffe3040101020103042c302a040a80001f880468617a656c0202010a02022c8704046d666b31040c40365ebe8c88f4ab6b1a2203040030818f040a80001f880468617a656c0400a27f0201020201000201003074307206082b06010201010100046657696e646f77732048617a656c20362e302e363030322053657276696365205061636b2032202053657276657220342e302c20456e74657270726973652045646974696f6e207838362046616d696c792036204d6f64656c203233205374657070696e672036"

	read_v3_response_pdu_request_id_4 = "306f020103300e020104020300ffe3040101020103042c302a040a80001f880468617a656c0202010a02022c8704046d666b31040c653dde6ad603d9ce5587dd1f0400302c040a80001f880468617a656c0400a21c0201040201000201003011300f06082b060102010103004303116531"
)

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// read_auth_failure_with_auto_discover
// 2012/11/16 11:36:26 snmp - invoke begin.
// 2012/11/16 11:36:26 snmp - read ok
// 2012/11/16 11:36:26 305f020103300e020101020300ffe3040100020103041c301a040a80001f880468617a656c0202010a02022c38040004000400302c040a80001f880468617a656c0400a81c0201010201000201003011300f060a2b060106030f01010400410108
// 2012/11/16 11:36:26 snmp - send success, get variableBindings[] from 127.0.0.1:161 with auth = '[noauth]' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[noauth]' and priv = '[nopriv]' and requestId='1. and identifier='1' and version='v3'
// 2012/11/16 11:36:26 snmp - send success, next variableBindings[1.3.6=''] from  with auth = '[md5]mfk12345\' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[md5]mfk12345\' and priv = '[nopriv]' and requestId='2. and identifier='2' and version='v3'
// 2012/11/16 11:36:27 snmp - read ok
// 2012/11/16 11:36:27 3063020103300e020102020300ffe30401000201030420301e040a80001f880468617a656c0202010a02022c3804046d666b3104000400302c040a80001f880468617a656c0400a81c0201020201000201003011300f060a2b060106030f01010500410104
// 2012/11/16 11:36:27 bad security level
// 2012/11/16 11:36:27 snmp - recv pdu failed, bad security level
// 2012/11/16 11:36:27 snmp - invoke end.
// GET SNMPv3 '' identifier: 1
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname:
//  user.auth_proto: 0
//  user.auth_key 0:
//  user.priv_proto: 0
//  user.priv_key 0:
//  engine boots=0, time=0, max_msg_size=10000, engine.engine_id:  0:
//  request_id=1 error_status=0 error_index=0
// REPORT SNMPv3 '' identifier: 1
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname:
//  user.auth_proto: 0
//  user.auth_key 0:
//  user.priv_proto: 0
//  user.priv_key 0:
//  engine boots=266, time=11320, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=1 error_status=0 error_index=0
//  [0]: 1.3.6.1.6.3.15.1.1.4.0=COUNTER 8
// GETNEXT SNMPv3 '' identifier: 2
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: 1a 10 c9 c9 2e c0 b7 c4 9e b6 a7 db 6f 76 d4 13
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=11320, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=2 error_status=0 error_index=0
//  [0]: 1.3.6=NULL
// SNMP: bad security level for auth.
const (
	auth_failed_discover_response_pdu = "305f020103300e020101020300ffe3040100020103041c301a040a80001f880468617a656c0202010a02022c38040004000400302c040a80001f880468617a656c0400a81c0201010201000201003011300f060a2b060106030f01010400410108"
	auth_failed_read_v3_response_pdu  = "3063020103300e020102020300ffe30401000201030420301e040a80001f880468617a656c0202010a02022c3804046d666b3104000400302c040a80001f880468617a656c0400a81c0201020201000201003011300f060a2b060106030f01010500410104"

	auth_error_discover_response_pdu = "305f020103300e020101020300ffe3040100020103041c301a040a80001f880468617a656c0202010a02022cbc040004000400302c040a80001f880468617a656c0400a81c0201010201000201003011300f060a2b060106030f0101040041010a"
	auth_error_read_v3_response_pdu  = "3066020103300e020102020300ffe3040101020103042c302a040a80001f880468617a656c0202010a02022cbc04046d666b33040c24d282b0859eaa16fed6045f04003023040a80001f880468617a656c0400a2130201020201100201003008300606022b060500"
)

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//read_priv_failed_with_auto_discover
// 2012/11/16 11:38:38 snmp - invoke begin.
// 2012/11/16 11:38:38 snmp - read ok
// 2012/11/16 11:38:38 305f020103300e020101020300ffe3040100020103041c301a040a80001f880468617a656c0202010a02022cbc040004000400302c040a80001f880468617a656c0400a81c0201010201000201003011300f060a2b060106030f0101040041010a
// 2012/11/16 11:38:38 snmp - send success, get variableBindings[] from 127.0.0.1:161 with auth = '[noauth]' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[noauth]' and priv = '[nopriv]' and requestId='1. and identifier='1' and version='v3'
// 2012/11/16 11:38:38 snmp - send success, next variableBindings[1.3.6=''] from  with auth = '[sha]mfk123456' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[sha]mfk123456' and priv = '[nopriv]' and requestId='2. and identifier='2' and version='v3'
// 2012/11/16 11:38:38 snmp - read ok
// 2012/11/16 11:38:38 3066020103300e020102020300ffe3040101020103042c302a040a80001f880468617a656c0202010a02022cbc04046d666b33040c24d282b0859eaa16fed6045f04003023040a80001f880468617a656c0400a2130201020201100201003008300606022b060500
// 2012/11/16 11:38:38 snmp - recv pdu failed, check pdu failed, Authorization error
// 2012/11/16 11:38:38 snmp - invoke end.
// GET SNMPv3 '' identifier: 1
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname:
//  user.auth_proto: 0
//  user.auth_key 0:
//  user.priv_proto: 0
//  user.priv_key 0:
//  engine boots=0, time=0, max_msg_size=10000, engine.engine_id:  0:
//  request_id=1 error_status=0 error_index=0
// REPORT SNMPv3 '' identifier: 1
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname:
//  user.auth_proto: 0
//  user.auth_key 0:
//  user.priv_proto: 0
//  user.priv_key 0:
//  engine boots=266, time=11452, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=1 error_status=0 error_index=0
//  [0]: 1.3.6.1.6.3.15.1.1.4.0=COUNTER 10
// GETNEXT SNMPv3 '' identifier: 2
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk3
//  user.auth_proto: 2
//  user.auth_key 20: 5b e2 b3 37 0e 7c d9 68 94 4c 3e d0 47 48 3d 66 cd 33 65 c5
//  user.priv_proto: 0
//  user.priv_key 20: 9c 14 fe 61 5e 86 2c ec 10 21 c2 a4 e6 bb ff 87 34 a5 3d 7f
//  engine boots=266, time=11452, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=2 error_status=0 error_index=0
//  [0]: 1.3.6=NULL
// RESPONSE SNMPv3 '' identifier: 2
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: 24 d2 82 b0 85 9e aa 16 fe d6 04 5f
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk3
//  user.auth_proto: 2
//  user.auth_key 20: 5b e2 b3 37 0e 7c d9 68 94 4c 3e d0 47 48 3d 66 cd 33 65 c5
//  user.priv_proto: 0
//  user.priv_key 20: 9c 14 fe 61 5e 86 2c ec 10 21 c2 a4 e6 bb ff 87 34 a5 3d 7f
//  engine boots=266, time=11452, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=2 error_status=16 error_index=0
//  [0]: 1.3.6=NULL
const (
	priv_failed_discover_response_pdu = "305f020103300e020101020300ffe3040100020103041c301a040a80001f880468617a656c0202010a02022cbc040004000400302c040a80001f880468617a656c0400a81c0201010201000201003011300f060a2b060106030f0101040041010a"
	priv_failed_read_v3_response_pdu  = "3063020103300e020102020300ffe30401000201030420301e040a80001f880468617a656c020201a10202150004046d666b3204000400302c040a80001f880468617a656c0400a81c0201000201000201003011300f060a2b060106030f01010600410104"
)

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// read_ok_with_engine_time_not_in_timewindow
// 2012/11/16 14:22:24 snmp - invoke begin.
// GET SNMPv3 '' identifier: 1
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname:
//  user.auth_proto: 0
//  user.auth_key 0:
//  user.priv_proto: 0
//  user.priv_key 0:
//  engine boots=0, time=0, max_msg_size=10000, engine.engine_id:  0:
//  request_id=1 error_status=0 error_index=0
// 2012/11/16 14:22:24 snmp - send success, get variableBindings[] from 127.0.0.1:161 with auth = '[noauth]' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[noauth]' and priv = '[nopriv]' and requestId='1. and identifier='1' and version='v3'
// 2012/11/16 14:22:24 snmp - read ok
// 2012/11/16 14:22:24 305f020103300e020101020300ffe3040100020103041c301a040a80001f880468617a656c0202010a0202531d040004000400302c040a80001f880468617a656c0400a81c0201010201000201003011300f060a2b060106030f0101040041010c
// REPORT SNMPv3 '' identifier: 1
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname:
//  user.auth_proto: 0
//  user.auth_key 0:
//  user.priv_proto: 0
//  user.priv_key 0:
//  engine boots=266, time=21277, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=1 error_status=0 error_index=0
//  [0]: 1.3.6.1.6.3.15.1.1.4.0=COUNTER 12
// GETNEXT SNMPv3 '' identifier: 2
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=21277, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=2 error_status=0 error_index=0
//  [0]: 1.3.6=NULL
// 2012/11/16 14:22:24 snmp - send success, next variableBindings[1.3.6=''] from  with auth = '[md5]mfk123456' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[md5]mfk123456' and priv = '[nopriv]' and requestId='2. and identifier='2' and version='v3'
// 2012/11/16 14:22:24 snmp - read ok
// 2012/11/16 14:22:24 3081d3020103300e020102020300ffe3040101020103042c302a040a80001f880468617a656c0202010a0202531d04046d666b31040cc80f5c654c15a1fd369df3b9040030818f040a80001f880468617a656c0400a27f0201020201000201003074307206082b06010201010100046657696e646f77732048617a656c20362e302e363030322053657276696365205061636b2032202053657276657220342e302c20456e74657270726973652045646974696f6e207838362046616d696c792036204d6f64656c203233205374657070696e672036
// RESPONSE SNMPv3 '' identifier: 2
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: c8 0f 5c 65 4c 15 a1 fd 36 9d f3 b9
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=21277, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=2 error_status=0 error_index=0
//  [0]: 1.3.6.1.2.1.1.1.0=OCTET STRING 102: 57 69 6e 64 6f 77 73 20 48 61 7a 65 6c 20 36 2e 30 2e 36 30 30 32 20 53 65 72 76 69 63 65 20 50 61 63 6b 20 32 20 20 53 65 72 76 65 72 20 34 2e 30 2c 20 45 6e 74 65 72 70 72 69 73 65 20 45 64 69 74 69 6f 6e 20 78 38 36 20 46 61 6d 69 6c 79 20 36 20 4d 6f 64 65 6c 20 32 33 20 53 74 65 70 70 69 6e 67 20 36
// 2012/11/16 14:22:24 snmp - recv pdu success, response variableBindings[1.3.6.1.2.1.1.1.0='57696e646f77732048617a656c20362e302e363030322053657276696365205061636b2032202053657276657220342e302c20456e74657270726973652045646974696f6e207838362046616d696c792036204d6f64656c203233205374657070696e672036'] from  with auth = '[md5]' and priv = '[nopriv]' and contextName='' and contextEngine='80001f880468617a656c and auth = '[md5]' and priv = '[nopriv]' and requestId='2. and identifier='2' and version='v3'
// 2012/11/16 14:22:24 snmp - invoke end.
// 2012/11/16 14:34:39 snmp - invoke begin.
// GETNEXT SNMPv3 '' identifier: 5
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=21277, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=5 error_status=0 error_index=0
//  [0]: 1.3.6=NULL
// 2012/11/16 14:34:39 snmp - send success, next variableBindings[1.3.6=''] from  with auth = '[md5]mfk123456' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[md5]mfk123456' and priv = '[nopriv]' and requestId='5. and identifier='5' and version='v3'
// 2012/11/16 14:34:39 snmp - read ok
// 2012/11/16 14:34:39 306f020103300e020105020300ffe3040101020103042c302a040a80001f880468617a656c0202010a020255fd04046d666b31040cce09c76a7cfa0a051b85cf7d0400302c040a80001f880468617a656c0400a81c0201050201000201003011300f060a2b060106030f01010200410101
// REPORT SNMPv3 '' identifier: 5
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: ce 09 c7 6a 7c fa 0a 05 1b 85 cf 7d
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=22013, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=5 error_status=0 error_index=0
//  [0]: 1.3.6.1.6.3.15.1.1.2.0=COUNTER 1
// GET SNMPv3 '' identifier: 6
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname:
//  user.auth_proto: 0
//  user.auth_key 0:
//  user.priv_proto: 0
//  user.priv_key 0:
//  engine boots=0, time=0, max_msg_size=10000, engine.engine_id:  0:
//  request_id=6 error_status=0 error_index=0
// 2012/11/16 14:34:39 snmp - read ok
// 2012/11/16 14:34:39 305f020103300e020106020300ffe3040100020103041c301a040a80001f880468617a656c0202010a020255fd040004000400302c040a80001f880468617a656c0400a81c0201060201000201003011300f060a2b060106030f0101040041010d
// 2012/11/16 14:34:39 snmp - send success, get variableBindings[] from 127.0.0.1:161 with auth = '[noauth]' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[noauth]' and priv = '[nopriv]' and requestId='6. and identifier='6' and version='v3'
// REPORT SNMPv3 '' identifier: 6
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname:
//  user.auth_proto: 0
//  user.auth_key 0:
//  user.priv_proto: 0
//  user.priv_key 0:
//  engine boots=266, time=22013, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=6 error_status=0 error_index=0
//  [0]: 1.3.6.1.6.3.15.1.1.4.0=COUNTER 13
// GETNEXT SNMPv3 '' identifier: 7
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=22013, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=7 error_status=0 error_index=0
//  [0]: 1.3.6=NULL
// 2012/11/16 14:34:39 snmp - send success, next variableBindings[1.3.6=''] from  with auth = '[md5]mfk123456' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[md5]mfk123456' and priv = '[nopriv]' and requestId='7. and identifier='7' and version='v3'
// 2012/11/16 14:34:39 snmp - read ok
// 2012/11/16 14:34:39 3081d3020103300e020107020300ffe3040101020103042c302a040a80001f880468617a656c0202010a020255fd04046d666b31040c1f72166bbe2d3eaa793709ad040030818f040a80001f880468617a656c0400a27f0201070201000201003074307206082b06010201010100046657696e646f77732048617a656c20362e302e363030322053657276696365205061636b2032202053657276657220342e302c20456e74657270726973652045646974696f6e207838362046616d696c792036204d6f64656c203233205374657070696e672036
// RESPONSE SNMPv3 '' identifier: 7
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: 1f 72 16 6b be 2d 3e aa 79 37 09 ad
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=22013, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=7 error_status=0 error_index=0
//  [0]: 1.3.6.1.2.1.1.1.0=OCTET STRING 102: 57 69 6e 64 6f 77 73 20 48 61 7a 65 6c 20 36 2e 30 2e 36 30 30 32 20 53 65 72 76 69 63 65 20 50 61 63 6b 20 32 20 20 53 65 72 76 65 72 20 34 2e 30 2c 20 45 6e 74 65 72 70 72 69 73 65 20 45 64 69 74 69 6f 6e 20 78 38 36 20 46 61 6d 69 6c 79 20 36 20 4d 6f 64 65 6c 20 32 33 20 53 74 65 70 70 69 6e 67 20 36
// 2012/11/16 14:34:39 snmp - recv pdu success, response variableBindings[1.3.6.1.2.1.1.1.0='57696e646f77732048617a656c20362e302e363030322053657276696365205061636b2032202053657276657220342e302c20456e74657270726973652045646974696f6e207838362046616d696c792036204d6f64656c203233205374657070696e672036'] from  with auth = '[md5]' and priv = '[nopriv]' and contextName='' and contextEngine='80001f880468617a656c and auth = '[md5]' and priv = '[nopriv]' and requestId='7. and identifier='7' and version='v3'
// 2012/11/16 14:34:39 snmp - invoke end.
// 2012/11/16 14:34:40 snmp - invoke begin.
// GETNEXT SNMPv3 '' identifier: 11
//  context_name:
//  context_engine 0:
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=22013, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=11 error_status=0 error_index=0
//  [0]: 1.3.6.1.2.1.1.4.0=NULL
// 2012/11/16 14:34:40 snmp - send success, next variableBindings[1.3.6.1.2.1.1.4.0=''] from  with auth = '[md5]mfk123456' and priv = '[nopriv]' and contextName='' and contextEngine=' and auth = '[md5]mfk123456' and priv = '[nopriv]' and requestId='11. and identifier='11' and version='v3'
// 2012/11/16 14:34:40 snmp - read ok
// 2012/11/16 14:34:40 3071020103300e02010b020300ffe3040101020103042c302a040a80001f880468617a656c0202010a020255fd04046d666b31040cc5a4212dbb7078e7035657170400302e040a80001f880468617a656c0400a21e02010b0201000201003013301106082b06010201010500040548617a656c
// RESPONSE SNMPv3 '' identifier: 11
//  context_name:
//  context_engine 10: 80 00 1f 88 04 68 61 7a 65 6c
//  msg_digest 12: c5 a4 21 2d bb 70 78 e7 03 56 57 17
//  msg_salt 8: 00 00 00 00 00 00 00 00
//  user.secname: mfk1
//  user.auth_proto: 1
//  user.auth_key 16: d8 62 0a 76 a5 06 1d b0 a5 12 73 54 c8 34 d7 d6
//  user.priv_proto: 0
//  user.priv_key 16: 1f 28 8e 0a 86 c6 f5 d0 86 26 d1 47 3d 32 f5 f1
//  engine boots=266, time=22013, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
//  request_id=11 error_status=0 error_index=0
//  [0]: 1.3.6.1.2.1.1.5.0=OCTET STRING 5: 48 61 7a 65 6c
// 2012/11/16 14:34:40 snmp - recv pdu success, response variableBindings[1.3.6.1.2.1.1.5.0='48617a656c'] from  with auth = '[md5]' and priv = '[nopriv]' and contextName='' and contextEngine='80001f880468617a656c and auth = '[md5]' and priv = '[nopriv]' and requestId='11. and identifier='11' and version='v3'
// 2012/11/16 14:34:40 snmp - invoke end.
const (
	timeout_1_discover_pdu         = "305f020103300e020101020300ffe3040100020103041c301a040a80001f880468617a656c0202010a0202531d040004000400302c040a80001f880468617a656c0400a81c0201010201000201003011300f060a2b060106030f0101040041010c"
	timeout_2_response_pdu         = "3081d3020103300e020102020300ffe3040101020103042c302a040a80001f880468617a656c0202010a0202531d04046d666b31040cc80f5c654c15a1fd369df3b9040030818f040a80001f880468617a656c0400a27f0201020201000201003074307206082b06010201010100046657696e646f77732048617a656c20362e302e363030322053657276696365205061636b2032202053657276657220342e302c20456e74657270726973652045646974696f6e207838362046616d696c792036204d6f64656c203233205374657070696e672036"
	timeout_2_response_bindings    = "[1.3.6.1.2.1.1.1.0='57696e646f77732048617a656c20362e302e363030322053657276696365205061636b2032202053657276657220342e302c20456e74657270726973652045646974696f6e207838362046616d696c792036204d6f64656c203233205374657070696e672036']"
	timeout_3_timeout_response_pdu = "306f020103300e020105020300ffe3040101020103042c302a040a80001f880468617a656c0202010a020255fd04046d666b31040cce09c76a7cfa0a051b85cf7d0400302c040a80001f880468617a656c0400a81c0201050201000201003011300f060a2b060106030f01010200410101"
	timeout_4_discover_pdu         = "305f020103300e020106020300ffe3040100020103041c301a040a80001f880468617a656c0202010a020255fd040004000400302c040a80001f880468617a656c0400a81c0201060201000201003011300f060a2b060106030f0101040041010d"
	timeout_5_response             = "3071020103300e02010b020300ffe3040101020103042c302a040a80001f880468617a656c0202010a020255fd04046d666b31040cc5a4212dbb7078e7035657170400302e040a80001f880468617a656c0400a21e02010b0201000201003013301106082b06010201010500040548617a656c"
)
