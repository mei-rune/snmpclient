package snmpclient

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestSendV3Failed(t *testing.T) {
	testSnmpWith(t, "0.0.0.0:0", "33.0.0.0:0", func(t *testing.T, cl Client, listener *snmpTestServer) {

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

		if !strings.Contains(err.Error(), "time out") {
			t.Errorf("except throw an timeout error, actual return %s", err.Error())
			return
		}
		//cl.FreePDU(pdu)
	})
}

func TestDisconnectWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		var trapError SnmpError
		var res, req PDU
		var err error

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, true)
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

		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		if "[1.3.6.1.2.1.1.3.0='1140017']" != res.GetVariableBindings().String() {
			t.Errorf("sendAndRecv pdu failed - res is error")
		}

		listener.Stop()

		req, err = cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}

		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if !strings.Contains(err.Error(), "time out") {
			t.Errorf("except throw an timeout error, actual return %s", err.Error())
			return
		}
		//cl.FreePDU(pdu, res)
	})
}

func TestDisconnectAndReconnectWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		var trapError SnmpError
		var res, req PDU
		var err error
		var trapCount int

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			trapCount = count
			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, true)
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
			case 3:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}
				svr.ReturnWith(discover_response_pdu)
			case 4:
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

		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if nil != trapError {
			t.Errorf("sendAndRecv trap failed - %s", trapError.Error())
			return
		}

		if "[1.3.6.1.2.1.1.3.0='1140017']" != res.GetVariableBindings().String() {
			t.Errorf("sendAndRecv pdu failed - res is error")
		}

		listener.Stop()

		req, err = cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}

		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if !strings.Contains(err.Error(), "time out") {
			t.Errorf("except throw an timeout error, actual return %s", err.Error())
			return
		}

		listener.Start()

		req, err = cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}

		res, err = cl.SendAndRecv(req, 2*time.Second)
		if nil != err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if !strings.Contains(err.Error(), "time out") {
			t.Errorf("except throw an timeout error, actual return %s", err.Error())
			return
		}

		if "[1.3.6.1.2.1.1.3.0='1140017']" != res.GetVariableBindings().String() {
			t.Errorf("sendAndRecv pdu failed - res is error")
		}

		if 4 != trapCount {
			t.Errorf("sendAndRecv trap count failed")
			return
		}
		//cl.FreePDU(pdu, res)
	})
}

func TestReadOkWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		var trapError SnmpError

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, true)
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

		if "[1.3.6.1.2.1.1.3.0='1140017']" != res.GetVariableBindings().String() {
			t.Errorf("sendAndRecv pdu failed - res is error")
		}
		//cl.FreePDU(pdu, res)
	})
}

func TestAuthFailureWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		var trapError SnmpError

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, true)
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

		_, err = cl.SendAndRecv(req, 2*time.Second)
		if nil == err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if SNMP_CODE_BADSECLEVEL != err.Code() {
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

func TestPrivFailureWhitv3Pdu(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		var trapError SnmpError

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU

			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, true)
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
				} else if 226 != pdu.(*V3PDU).engine.engine_boots {
					trapError = Error(SNMP_CODE_FAILED, "engine boots is error.")
				} else if 11452 != pdu.(*V3PDU).engine.engine_time {
					trapError = Error(SNMP_CODE_FAILED, "engine time is error.")
				}
				svr.ReturnWith(priv_failed_read_v3_response_pdu)
			}
		})

		req, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}

		_, err = cl.SendAndRecv(req, 2*time.Second)
		if nil == err {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			return
		}

		if SNMP_CODE_BADSECLEVEL != err.Code() {
			t.Errorf("sendAndRecv pdu failed - %s", err.Error())
			t.Log("except is SNMP_CODE_BADSECLEVEL")
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

func TestAutoRedisconverWhitEngineIdTimeout(t *testing.T) {
	testSnmpWith(t, "127.0.0.1:0", "", func(t *testing.T, cl Client, listener *snmpTestServer) {
		var trapError SnmpError
		var sq_count int = 0

		listener.TrapWith(func(svr *snmpTestServer, count int, bytes []byte) {
			var pdu PDU
			sq_count = count
			pdu, trapError = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, true)
			switch count {
			case 1:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}
				svr.ReturnWith(timeout_1_discover_pdu)
			case 2:
				//  engine boots=266, time=21277, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
				} else if 226 != pdu.(*V3PDU).engine.engine_boots {
					trapError = Error(SNMP_CODE_FAILED, "engine boots is error.")
				} else if 21277 != pdu.(*V3PDU).engine.engine_time {
					trapError = Error(SNMP_CODE_FAILED, "engine time is error.")
				}
				svr.ReturnWith(timeout_2_response_pdu)

			case 3:
				//  engine boots=266, time=21277, max_msg_size=10000, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
				} else if 226 != pdu.(*V3PDU).engine.engine_boots {
					trapError = Error(SNMP_CODE_FAILED, "engine boots is error.")
				} else if 21277 != pdu.(*V3PDU).engine.engine_time {
					trapError = Error(SNMP_CODE_FAILED, "engine time is error.")
				}
				svr.ReturnWith(timeout_3_timeout_response_pdu)
			case 4:
				if 0 != pdu.GetVariableBindings().Len() {
					trapError = Error(SNMP_CODE_FAILED, "bindings len is not zero.")
				}
				svr.ReturnWith(timeout_4_discover_pdu)
			case 5:
				//  engine boots=266, time=22013, max_msg_size=65507, engine.engine_id:  10: 80 00 1f 88 04 68 61 7a 65 6c
				if "80001f880468617a656c" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
					trapError = Error(SNMP_CODE_FAILED, "engine id is error.")
				} else if 226 != pdu.(*V3PDU).engine.engine_boots {
					trapError = Error(SNMP_CODE_FAILED, "engine boots is error.")
				} else if 22013 != pdu.(*V3PDU).engine.engine_time {
					trapError = Error(SNMP_CODE_FAILED, "engine time is error.")
				}

				svr.ReturnWith(timeout_5_response)
			}
		})

		req, err := cl.CreatePDU(SNMP_PDU_GET, SNMP_V3)
		if nil != err {
			t.Errorf("create pdu failed - %s", err.Error())
			return
		}

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

		if timeout_2_response_bindings == res.GetVariableBindings().String() {
			t.Errorf("sendAndRecv pdu failed - res is error")
			t.Log("except is " + timeout_2_response_bindings)
			t.Log("actual is " + res.GetVariableBindings().String())
			return
		}

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

		if "[1.3.6.1.2.1.1.5.0='48617a656c']" == res.GetVariableBindings().String() {
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
