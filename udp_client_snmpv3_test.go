package snmpclient

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

var excepted = "[1.3.6.1.2.1.1.1.0='57696e646f77732048617a656c20362e302e363030322053657276696365205061636b2032202053657276657220342e302c20456e74657270726973652045646974696f6e207838362046616d696c792036204d6f64656c203233205374657070696e672036']"

func TestV3SendV3Failed(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "33.0.0.0:0", func(t *testing.T, cl Client, listener *snmpTestServer) {

		cl.(*UdpClient).next_id = 233
		pdu, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V1)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		pdu.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk1", "snmp.auth_pass": "[md5]mfk123456"})

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

func TestV3DisconnectWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		cl.(*UdpClient).SetNextId(0)

		var trapError SnmpError
		var res, req PDU
		var err error

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, *dump_pdu)
			switch count {
			case 1:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}
				svr.ReturnWith(discover_response_pdu)
			case 2:
				//boots=266, time=11399, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
				}
				svr.ReturnWith(read_v3_response_pdu)
			}
		})

		req, err = cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk1", "snmp.auth_pass": "[md5]mfk123456"})

		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			fmt.Printf("sendAndRecv pdu failed - %s\r\n", err.Error())
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		if excepted != res.GetVariableBindings().String() {
			t.Errorf("sendAndRecv pdu failed - res is error")
		}

		listener.Stop()

		req, err = cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk1", "snmp.auth_pass": "[md5]mfk123456"})

		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil == err {
			t.Errorf("excepted error is not nil, but actual is nil")
			return
		}

		// if !strings.Contains(err.Error(), "127.0.0.1:0") {
		// 	t.Errorf("except throw an send error, actual return %s", err.Error())
		// 	return
		// }
		//cl.FreePDU(pdu, res)
	})
}

func TestV3DisconnectAndReconnectWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		cl.(*UdpClient).SetNextId(0)

		var trapError SnmpError
		var res, req PDU
		var err error
		var trapCount int

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			trapCount = count
			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, *dump_pdu)
			switch count {
			case 1:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}
				svr.ReturnWith(discover_response_pdu)
			case 2:
				//boots=266, time=11399, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
				}
				svr.ReturnWith(read_v3_response_pdu)
			// case 3:
			// 	if 0 != pdu.GetVariableBindings().Len() {
			// 		trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
			// 	}
			// 	svr.ReturnWith(discover_response_pdu)
			case 3:
				//boots=266, time=11399, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
				}
				svr.ReturnWith(read_v3_response_pdu_request_id_4)
			}
		})

		req, err = cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk1", "snmp.auth_pass": "[md5]mfk123456"})

		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		if excepted != res.GetVariableBindings().String() {
			t.Errorf("sendAndRecv pdu failed - res is error")
			t.Error("excepted is", excepted)
			t.Error("actual is", res.GetVariableBindings().String())
		}

		listener.Stop()

		req, err = cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk1", "snmp.auth_pass": "[md5]mfk123456"})

		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil == err {
			t.Errorf("excepted error is not nil, but actual is nil")
			return
		}

		if !strings.Contains(err.Error(), "127.0.0.1:") {
			t.Logf("[WARN]   except throw an send error, actual return %s", err.Error())
		}

		listener.Start()

		req, err = cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk1", "snmp.auth_pass": "[md5]mfk123456"})
		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if "[1.3.6.1.2.1.1.3.0='1140017']" != res.GetVariableBindings().String() {
			t.Errorf("sendAndRecv pdu failed - res is error")
		}

		if 3 != trapCount {
			t.Errorf("sendAndRecv trap count failed")
			return
		}
		//cl.FreePDU(pdu, res)
	})
}

func TestV3ReadOkWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		cl.(*UdpClient).SetNextId(0)

		var trapError SnmpError

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, *dump_pdu)
			switch count {
			case 1:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}
				svr.ReturnWith(discover_response_pdu)
			case 2:
				//boots=266, time=11399, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
				}
				svr.ReturnWith(read_v3_response_pdu)
			}
		})

		req, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk1", "snmp.auth_pass": "[md5]mfk123456"})

		res, err := cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		if nil == res {
			t.Errorf("sendAndRecv pdu failed - res is nil")
		}

		if excepted != res.GetVariableBindings().String() {
			t.Error("sendAndRecv pdu failed - res is error")
			t.Error("excepted is", excepted)
			t.Error("actual is", res.GetVariableBindings().String())
		}
		//cl.FreePDU(pdu, res)
	})
}

func TestV3AuthFailureWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		cl.(*UdpClient).SetNextId(0)

		var trapError SnmpError

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, *dump_pdu)
			switch count {
			case 1:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}
				svr.ReturnWith(auth_failed_discover_response_pdu)
			case 2:
				//boots=266, time=11399, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
				}
				svr.ReturnWith(auth_failed_read_v3_response_pdu)
			}
		})

		req, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk1", "snmp.auth_pass": "[md5]mfk123456"})

		_, err = cl.SendAndRecv(req, 2*time.Second)
		if nil == err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if SNMP_CODE_BADDIGEST != err.Code() {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		//cl.FreePDU(pdu, res)
	})
}

func TestV3AuthErrorFailureWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		cl.(*UdpClient).SetNextId(0)

		var trapError SnmpError

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, *dump_pdu)
			switch count {
			case 1:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}
				svr.ReturnWith(auth_error_discover_response_pdu)
			case 2:
				//  engine boots=266, time=11452, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
					// } else if 226 != pdu.(*V3PDU).engine.engine_boots {
					// 	trapError = Error(SNMP_CODE_FAILED, "engine boots is error.")
					// } else if 11452 != pdu.(*V3PDU).engine.engine_time {
					// 	trapError = Error(SNMP_CODE_FAILED, "engine time is error.")
				}
				svr.ReturnWith(auth_error_read_v3_response_pdu)
			}
		})

		req, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk1", "snmp.auth_pass": "[md5]mfk123456"})

		_, err = cl.SendAndRecv(req, 2*time.Second)
		if nil == err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if SNMP_CODE_ERR_AUTH_ERR != err.Code() {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			t.Log("except is SNMP_CODE_ERR_AUTH_ERR")
			t.Logf("actual is %d", err.Code())
			return
		}

		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		//cl.FreePDU(pdu, res)
	})
}

func TestV3PrivFailureWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		cl.(*UdpClient).SetNextId(0)

		var trapError SnmpError

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, *dump_pdu)
			switch count {
			case 1:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}
				svr.ReturnWith(priv_failed_discover_response_pdu)
			case 2:
				//  engine boots=266, time=11452, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
					// } else if 226 != pdu.(*V3PDU).engine.engine_boots {
					// 	trapError = Error(SNMP_CODE_FAILED, "engine boots is error.")
					// } else if 11452 != pdu.(*V3PDU).engine.engine_time {
					// 	trapError = Error(SNMP_CODE_FAILED, "engine time is error.")
				}
				svr.ReturnWith(priv_failed_read_v3_response_pdu)
			}
		})

		req, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk2", "snmp.auth_pass": "[md5]mfk123456", "snmp.priv_pass": "[aes]mfk123456"})

		_, err = cl.SendAndRecv(req, 2*time.Second)
		if nil == err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if SNMP_CODE_EDECRYPT != err.Code() {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			t.Log("except is SNMP_CODE_EDECRYPT")
			t.Logf("actual is %d", err.Code())
			return
		}

		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		//cl.FreePDU(pdu, res)
	})
}

func TestV3AutoRedisconverWhitEngineIdTimeout(t *testing.T) {
	t.Skip("next")
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		cl.(*UdpClient).SetNextId(0)

		var trapError SnmpError
		var sq_count int = 0

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU
			sq_count = count
			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, *dump_pdu)
			switch count {
			case 1:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}

				fmt.Println("timeout_1_response_pdu")
				svr.ReturnWith(timeout_1_discover_pdu)
			case 2:
				//  engine boots=266, time=21277, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
					// } else if 0 != pdu.(*V3PDU).engine.engine_boots {
					// 	trapError = Error(SNMP_CODE_FAILED, "engine boots is error.")
					// } else if 0 != pdu.(*V3PDU).engine.engine_time {
					// 	trapError = Error(SNMP_CODE_FAILED, "engine time is error.")
				}
				fmt.Println("timeout_2_response_pdu")
				svr.ReturnWith(timeout_2_response_pdu)

			case 3:
				//  engine boots=266, time=21277, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
					// } else if 226 != pdu.(*V3PDU).engine.engine_boots {
					// 	trapError = Error(SNMP_CODE_FAILED, "engine boots is error.")
					// } else if 21277 != pdu.(*V3PDU).engine.engine_time {
					// 	trapError = Error(SNMP_CODE_FAILED, "engine time is error.")
				}
				fmt.Println("timeout_3_timeout_response_pdu")
				svr.ReturnWith(timeout_3_timeout_response_pdu)
			case 4:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}
				fmt.Println("timeout_4_discover_pdu")
				svr.ReturnWith(timeout_4_discover_pdu)
			case 5:
				//  engine boots=266, time=22013, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
					// } else if 226 != pdu.(*V3PDU).engine.engine_boots {
					// 	trapError = Error(SNMP_CODE_FAILED, "engine boots is error.")
					// } else if 22013 != pdu.(*V3PDU).engine.engine_time {
					// 	trapError = Error(SNMP_CODE_FAILED, "engine time is error.")
				}
				fmt.Println("timeout_5_response")
				svr.ReturnWith(timeout_5_response)
			}
		})

		req, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}
		req.Init(map[string]string{"snmp.secmodel": "usm", "snmp.secname": "mfk1", "snmp.auth_pass": "[md5]mfk123456"})

		res, err := cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}
		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		if nil == res {
			t.Errorf("sendAndRecv pdu failed - res is nil")
			return
		}

		if timeout_2_response_bindings != res.GetVariableBindings().String() {
			t.Errorf("sendAndRecv pdu failed - res is error")
			t.Log("except is " + timeout_2_response_bindings)
			t.Log("actual is " + res.GetVariableBindings().String())
			return
		}
		//cl.(*UdpClient).next_id = 4

		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		if nil == res {
			t.Errorf("sendAndRecv pdu failed - res is nil")
			return
		}

		if timeout_2_response_bindings != res.GetVariableBindings().String() {
			t.Errorf("sendAndRecv pdu failed - res is error")
			t.Log("except is " + timeout_2_response_bindings)
			t.Log("actual is " + res.GetVariableBindings().String())
			return
		}

		if 5 != sq_count {
			t.Errorf("sendAndRecv pdu failed - count is error")
			return
		}

		//cl.FreePDU(pdu, res)
	})
}
