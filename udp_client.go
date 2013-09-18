package snmpclient

// #include "bsnmp/config.h"
// #include "bsnmp/asn1.h"
// #include "bsnmp/snmp.h"
// #include "bsnmp/gobindings.h"
import "C"
import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	maxPDUSize  = flag.Uint("maxPDUSize", 2048, "set max size of pdu")
	deadTimeout = flag.Int("deadTimeout", 1, "set timeout(Minute) of client to dead")
)

type pendingRequest struct {
	client *UdpClient

	pdu      PDU
	callback func(PDU, SnmpError)
}

func (req *pendingRequest) reply(result PDU, err SnmpError) {

	if req.client.DEBUG.IsEnabled() {
		if nil != err {
			req.client.DEBUG.Printf("[snmp] - recv pdu failed, %v", err)
		} else {
			req.client.DEBUG.Printf("[snmp] - recv pdu success, %v", result)
		}
	}

	if nil == req {
		panic("req is nil")
	}

	if nil == req.callback {
		panic("callback is nil")
	}

	req.callback(result, err)
}

type UdpClient struct {
	DEBUG, ERROR Writer
	status       int32
	c            chan func()
	wait         sync.WaitGroup
	next_id      int
	host         string
	cached_bytes []byte
	engine       snmpEngine
	conn         *net.UDPConn
	pendings     map[int]*pendingRequest

	lastActive time.Time
}

func NewSnmpClient(host string) (Client, SnmpError) {
	return NewSnmpClientWith(host, &nullWriter{}, &nullWriter{})
}

func NewSnmpClientWith(host string, debugWriter, errorWriter Writer) (Client, SnmpError) {
	client := &UdpClient{status: 1,
		host:       NormalizeAddress(host),
		lastActive: time.Now(),
		c:          make(chan func())}
	client.pendings = make(map[int]*pendingRequest)
	client.DEBUG = debugWriter
	client.ERROR = errorWriter

	if client.engine.max_msg_size <= 0 {
		client.engine.max_msg_size = uint(*maxPDUSize)
	}

	client.cached_bytes = make([]byte, int(client.engine.max_msg_size))

	go client.serve()
	client.wait.Add(1)
	return client, nil
}

func (client *UdpClient) Close() {
	if !atomic.CompareAndSwapInt32(&client.status, 1, 0) {
		return
	}
	client.wait.Wait()
}

func (client *UdpClient) serve() {
	defer func() {
		if e := recover(); nil != e {
			var buffer bytes.Buffer
			buffer.WriteString(fmt.Sprintf("[panic]%v", e))
			for i := 1; ; i += 1 {
				_, file, line, ok := runtime.Caller(i)
				if !ok {
					break
				}
				buffer.WriteString(fmt.Sprintf("    %s:%d\r\n", file, line))
			}
			client.ERROR.Print(buffer.String())
		}
		client.wait.Done()
	}()

	defer func() {
		client.onDisconnection(nil)
		client.safelyKillConnection()
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for 1 == atomic.LoadInt32(&client.status) {
		select {
		case f := <-client.c:
			client.executeCommand(f)
		case <-ticker.C:
			client.fireTick()
		}
	}

	next := true
	for next {
		select {
		case f := <-client.c:
			client.executeCommand(f)
		default:
			next = false
		}
	}
}

func (client *UdpClient) fireTick() {
}

func (client *UdpClient) executeCommand(cb func()) {
	defer func() {
		if e := recover(); nil != e {
			var buffer bytes.Buffer
			buffer.WriteString(fmt.Sprintf("[snmp, panic][%s] %v", client.host, e))
			for i := 1; ; i += 1 {
				_, file, line, ok := runtime.Caller(i)
				if !ok {
					break
				}
				buffer.WriteString(fmt.Sprintf("    %s:%d\r\n", file, line))
			}
			client.DEBUG.Print(buffer.String())
		}
	}()

	cb()
}

func (client *UdpClient) returnError(timeout time.Duration, cb func() error) error {
	c := make(chan error)
	defer close(c)

	client.c <- func() {
		defer func() {
			if e := recover(); nil != e {
				var buffer bytes.Buffer
				buffer.WriteString(fmt.Sprintf("[panic]%v", e))
				for i := 1; ; i += 1 {
					_, file, line, ok := runtime.Caller(i)
					if !ok {
						break
					}
					buffer.WriteString(fmt.Sprintf("    %s:%d\r\n", file, line))
				}
				c <- errors.New(buffer.String())
			}
		}()

		c <- cb()
	}

	select {
	case res := <-c:
		return res
	case <-time.After(timeout):
		return TimeoutError
	}
}

type client_request struct {
	pdu PDU
	e   SnmpError
}

func (client *UdpClient) returnPDU(timeout time.Duration, cb func(reply_pdu func(pdu PDU, e SnmpError))) (PDU, SnmpError) {
	c := make(chan *client_request)

	client.c <- func() {
		is_reply := false
		reply := func(pdu PDU, e SnmpError) {
			if is_reply {
				return
			}

			is_reply = true
			c <- &client_request{pdu: pdu, e: e}
			close(c)
		}

		defer func() {
			if e := recover(); nil != e {
				var buffer bytes.Buffer
				buffer.WriteString(fmt.Sprintf("[panic]%v", e))
				for i := 1; ; i += 1 {
					_, file, line, ok := runtime.Caller(i)
					if !ok {
						break
					}
					buffer.WriteString(fmt.Sprintf("    %s:%d\r\n", file, line))
				}
				c <- &client_request{pdu: nil, e: Error(SNMP_CODE_FAILED, buffer.String())}
			}
		}()

		cb(reply)
	}

	//fmt.Println("TIMEOUT", timeout)
	select {
	case res := <-c:
		//fmt.Println("TIMEOUT1", timeout)
		return res.pdu, res.e
	case <-time.After(timeout):
		//fmt.Println("TIMEOUT2", timeout)
		return nil, newError(SNMP_CODE_TIMEOUT, TimeoutError, "")
	}
}

func (client *UdpClient) returnString(timeout time.Duration, cb func() string) string {
	c := make(chan string)

	client.c <- func() {
		defer func() {
			if e := recover(); nil != e {
				var buffer bytes.Buffer
				buffer.WriteString(fmt.Sprintf("[panic]%v", e))
				for i := 1; ; i += 1 {
					_, file, line, ok := runtime.Caller(i)
					if !ok {
						break
					}
					buffer.WriteString(fmt.Sprintf("    %s:%d\r\n", file, line))
				}
				c <- buffer.String()
			}
		}()

		c <- cb()
	}

	select {
	case res := <-c:
		return res
	case <-time.After(timeout):
		return "[panic]time out"
	}
}

func (client *UdpClient) Stats() interface{} {
	return map[string]interface{}{"pendings_requests": len(client.pendings), "queue": len(client.c)}
}

func (client *UdpClient) Test() error {
	return client.returnError(1*time.Minute, func() error {
		if time.Now().After(client.lastActive.Add(time.Duration(*deadTimeout) * time.Minute)) {
			return errors.New("it is expired.")
		}
		return nil
	})
}

func (client *UdpClient) CreatePDU(op SnmpType, version SnmpVersion) (PDU, SnmpError) {
	if op < 0 || SNMP_PDU_REPORT < op {
		return nil, Errorf(SNMP_CODE_FAILED, "unsupported pdu type: %d", op)
	}

	switch version {
	case SNMP_V1, SNMP_V2C:
		return &V2CPDU{op: op, version: version}, nil
	case SNMP_V3:
		return &V3PDU{op: op}, nil
	}
	return nil, Errorf(SNMP_CODE_FAILED, "unsupported version: %d", version)
}

func toSnmpCodeError(e error) SnmpError {
	if err, ok := e.(SnmpError); ok {
		return err
	}
	return newError(SNMP_CODE_FAILED, e, "")
}

func (client *UdpClient) SendAndRecv(req PDU, timeout time.Duration) (pdu PDU, err SnmpError) {
	if timeout > 1*time.Minute {
		timeout = 1 * time.Minute
	}
	pdu, err = client.returnPDU(timeout, func(reply func(pdu PDU, e SnmpError)) {
		client.handleSend(reply, req)
	})

	if nil != err && SNMP_CODE_TIMEOUT == err.Code() && 0 != req.GetRequestID() {
		client.c <- func() {
			delete(client.pendings, req.GetRequestID())
		}
	}

	return
}

func (client *UdpClient) createConnect() SnmpError {
	if nil != client.conn {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", client.host)
	if nil != err {
		return newError(SNMP_CODE_FAILED, err, "parse address failed")
	}
	client.conn, err = net.DialUDP("udp", nil, addr)
	if nil != err {
		return newError(SNMP_CODE_FAILED, err, "bind udp port failed")
	}

	go client.readUDP(client.conn)
	return nil
}

func (client *UdpClient) discoverEngine(fn func(PDU, SnmpError)) {

	if client.DEBUG.IsEnabled() {
		client.DEBUG.Printf("snmp - discover snmp engine")
	}

	usm := &USM{auth_proto: SNMP_AUTH_NOAUTH, priv_proto: SNMP_PRIV_NOPRIV}
	pdu := &V3PDU{op: SNMP_PDU_GET, securityModel: usm}
	client.sendPdu(pdu, fn)
}

func (client *UdpClient) sendV3PDU(reply func(pdu PDU, e SnmpError), pdu *V3PDU, autoDiscoverEngine bool) {
	if nil == pdu.securityModel {
		reply(nil, Error(SNMP_CODE_FAILED, "securityModel is nil"))
		return
	}

	if !pdu.securityModel.IsLocalize() {
		if nil == pdu.engine {
			if client.DEBUG.IsEnabled() {
				client.DEBUG.Printf("snmp - send failed, nil == pdu.engine, " + pdu.String())
			}
			reply(nil, Error(SNMP_CODE_FAILED, "nil == pdu.engine"))
			return
		}
		pdu.securityModel.Localize(pdu.engine.engine_id)
	}

	if autoDiscoverEngine {
		client.sendPdu(pdu, func(resp PDU, err SnmpError) {
			if nil != err {
				switch err.Code() {
				case SNMP_CODE_NOTINTIME, SNMP_CODE_BADENGINE:

					if nil != pdu.engine {
						pdu.engine.engine_id = nil
					}
					client.engine.engine_id = nil
					client.discoverEngineAndSend(reply, pdu)
					return
				}
			}

			if client.DEBUG.IsEnabled() {
				if nil != err {
					client.DEBUG.Printf("[snmpv3] - recv pdu failed, %v", err)
				} else {
					client.DEBUG.Printf("[snmpv3] - recv pdu success, %v", resp)
				}
			}

			reply(resp, err)
		})
	} else {
		client.sendPdu(pdu, reply)
	}
}

func (client *UdpClient) discoverEngineAndSend(reply func(pdu PDU, e SnmpError), pdu *V3PDU) {

	if nil != pdu.engine && nil != pdu.engine.engine_id && 0 != len(pdu.engine.engine_id) {
		client.sendV3PDU(reply, pdu, false)
		return
	}

	if nil != client.engine.engine_id && 0 != len(client.engine.engine_id) {
		if nil == pdu.engine {
			pdu.engine = &client.engine
		} else {
			pdu.engine.CopyFrom(&client.engine)
		}
		client.sendV3PDU(reply, pdu, true)
		return
	}

	client.discoverEngine(func(resp PDU, err SnmpError) {
		if nil == resp {
			if nil != err {
				err = newError(err.Code(), err, "discover engine failed")
			} else {
				err = Error(SNMP_CODE_FAILED, "discover engine failed - return nil pdu")
			}

			if client.DEBUG.IsEnabled() {
				client.DEBUG.Printf("snmp - recv pdu, " + err.Error())
			}
			reply(nil, err)
			return
		}
		v3, ok := resp.(*V3PDU)
		if !ok {

			if nil != err {
				err = newError(err.Code(), err, "discover engine failed - oooooooooooo! it is not v3pdu")
			} else {
				err = Error(SNMP_CODE_FAILED, "discover engine failed - oooooooooooo! it is not v3pdu")
			}

			if client.DEBUG.IsEnabled() {
				client.DEBUG.Printf("snmp - recv pdu, " + err.Error())
			}

			reply(nil, err)
			return
		}

		client.engine.CopyFrom(v3.engine)
		if nil == pdu.engine {
			pdu.engine = &client.engine
		} else {
			pdu.engine.engine_id = client.engine.engine_id
		}

		client.sendV3PDU(reply, pdu, false)
	})
}

func (client *UdpClient) readUDP(conn *net.UDPConn) {
	var err error

	defer func() {
		client.conn = nil
		if err := recover(); nil != err {
			client.ERROR.Print(err)
		} else {
			client.ERROR.Print("read connection complete, exit")
		}
		conn.Close()
	}()

	for 1 == atomic.LoadInt32(&client.status) {
		var length int
		var bytes []byte

		bytes = make([]byte, *maxPDUSize)
		length, err = conn.Read(bytes)

		if 1 != atomic.LoadInt32(&client.status) {
			break
		}

		if nil != err {
			client.ERROR.Print(err)
			break
		}

		if client.DEBUG.IsEnabled() {
			client.DEBUG.Printf("snmp - read ok")
			client.DEBUG.Print(hex.EncodeToString(bytes[:length]))
		}

		func(buf []byte) {
			client.c <- func() { client.handleRecv(buf) }
		}(bytes[:length])
	}

	if 1 == atomic.LoadInt32(&client.status) {
		client.c <- func() { client.onDisconnection(err) }
	}
}

func (client *UdpClient) onDisconnection(err error) {
	e := newError(SNMP_CODE_BADNET, err, "read from '"+client.host+"' failed")
	for _, req := range client.pendings {
		req.reply(nil, e)
	}
	client.pendings = make(map[int]*pendingRequest)
}

func (client *UdpClient) handleRecv(bytes []byte) {
	var buffer C.asn_buf_t
	var pdu C.snmp_pdu_t
	var result PDU
	var req *pendingRequest
	var ok bool

	C.set_asn_u_ptr(&buffer.asn_u, (*C.char)(unsafe.Pointer(&bytes[0])))
	buffer.asn_len = C.size_t(len(bytes))

	err := DecodePDUHeader(&buffer, &pdu)
	if nil != err {
		client.ERROR.Print(err)
		return
	}
	defer C.snmp_pdu_free(&pdu)

	if uint32(SNMP_V3) == pdu.version {

		req, ok = client.pendings[int(pdu.identifier)]
		if !ok {
			client.ERROR.Printf("not found request with requestId = %d, %d.\r\n", int(pdu.identifier), int(pdu.request_id))
			for i, _ := range client.pendings {
				client.ERROR.Print(i)
			}
			return
		}
		delete(client.pendings, int(pdu.identifier))

		v3old, ok := req.pdu.(*V3PDU)
		if !ok {
			err = Error(SNMP_CODE_FAILED, "receive pdu is a v3 pdu.")
			goto complete
		}
		usm, ok := v3old.securityModel.(*USM)
		if !ok {
			err = Error(SNMP_CODE_FAILED, "receive pdu is not usm.")
			goto complete
		}
		err = FillUser(&pdu, usm.auth_proto, usm.localization_auth_key,
			usm.priv_proto, usm.localization_priv_key)
		if nil != err {
			client.ERROR.Print(err.Error())
			goto complete
		}

		err = DecodePDUBody(&buffer, &pdu)
		if nil != err {
			client.ERROR.Print(err.Error())
			goto complete
		}

		if client.DEBUG.IsEnabled() {
			C.snmp_pdu_dump(&pdu)
		}

		var v3 V3PDU
		_, err = v3.decodePDU(&pdu)
		result = &v3
	} else {
		err = DecodePDUBody(&buffer, &pdu)
		if nil != err {
			client.ERROR.Print(err.Error())
			return
		}

		req, ok = client.pendings[int(pdu.request_id)]
		if !ok {
			client.ERROR.Printf("not found request with requestId = %d.\r\n", int(pdu.request_id))
			return
		}
		delete(client.pendings, int(pdu.request_id))

		if client.DEBUG.IsEnabled() {
			C.snmp_pdu_dump(&pdu)
		}

		var v2 V2CPDU
		_, err = v2.decodePDU(&pdu)
		result = &v2
	}

complete:
	req.reply(result, err)
}

func (client *UdpClient) handleSend(reply func(pdu PDU, err SnmpError), pdu PDU) {

	client.lastActive = time.Now()

	var err error = nil
	if nil == client.conn {
		err = client.createConnect()
		if nil != err {
			goto failed
		}
	}

	if SNMP_V3 == pdu.GetVersion() {
		v3, ok := pdu.(*V3PDU)
		if !ok {
			err = errors.New("oooooooooooo! it is not v3pdu.")
			goto failed
		}

		client.discoverEngineAndSend(reply, v3)
		return
	}

	client.sendPdu(pdu, reply)
	return
failed:

	if client.ERROR.IsEnabled() {
		client.ERROR.Print("snmp - send failed, " + err.Error() + " " + pdu.String())
	}

	reply(nil, toSnmpCodeError(err))
	return
}

func (client *UdpClient) safelyKillConnection() {
	defer func() {
		client.conn = nil
		if err := recover(); nil != err {
			client.ERROR.Print(err)
		}
	}()
	if nil != client.conn {
		client.conn.Close()
		client.conn = nil
	}
}

func (client *UdpClient) sendPdu(pdu PDU, callback func(PDU, SnmpError)) {
	if nil == callback {
		panic("'callback' is nil")
	}

	var bytes []byte = nil
	var err SnmpError = nil
	var e error = nil
	client.next_id++
	pdu.SetRequestID(client.next_id)

	_, ok := client.pendings[pdu.GetRequestID()]
	if ok {
		err = Error(SNMP_CODE_FAILED, "identifier is repected.")
		goto failed
	}

	bytes, err = EncodePDU(pdu, client.cached_bytes, client.DEBUG.IsEnabled())
	if nil != err {
		err = newError(err.Code(), err, "encode pdu failed")
		goto failed
	}

	client.pendings[pdu.GetRequestID()] = &pendingRequest{client: client, pdu: pdu, callback: callback}

	_, e = client.conn.Write(bytes)
	if nil != e {
		client.safelyKillConnection()
		err = newError(SNMP_CODE_BADNET, e, "send pdu failed")
		goto failed
	}

	if client.DEBUG.IsEnabled() {
		client.DEBUG.Print("snmp - send success, " + pdu.String())
		client.DEBUG.Print(hex.EncodeToString(bytes))
	}

	return
failed:

	if client.ERROR.IsEnabled() {
		client.ERROR.Print("snmp - send failed, " + err.Error() + ", " + pdu.String())
	}

	delete(client.pendings, pdu.GetRequestID())
	callback(nil, err)
	return
}

func (client *UdpClient) FreePDU(pdus ...PDU) {

}
