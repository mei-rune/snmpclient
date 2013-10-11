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
	"expvar"
	"flag"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const default_timeout = 30 * time.Second

var (
	maxPDUSize  = flag.Uint("maxPDUSize", 2048, "set max size of pdu")
	deadTimeout = flag.Int("deadTimeout", 1, "set timeout(Minute) of client to dead")

	disconnectError = errors.New("connection is disconnected.")
)

// type clientReply interface {
// 	reply(pdu PDU, e SnmpError)
// }

type clientRequest struct {
	c         chan *clientRequest
	timestamp int64
	timeout   time.Duration
	request   PDU
	response  PDU
	e         SnmpError
	cb        func(pdu PDU, e SnmpError)
}

func (cr *clientRequest) reply(pdu PDU, e SnmpError) {
	if nil != cr.cb {
		cr.cb(pdu, e)
		return
	}

	cr.response = pdu
	cr.e = e
	cr.c <- cr
}

var (
	requests_mutex sync.Mutex
	requests_cache = newRequestBuffer(make([]*clientRequest, 200))
)

func init() {
	expvar.Publish("udp_request_cache", expvar.Func(func() interface{} {
		requests_mutex.Lock()
		size := requests_cache.Size()
		requests_mutex.Unlock()
		return size
	}))
}

func newRequest() *clientRequest {
	requests_mutex.Lock()
	cached := requests_cache.Pop()
	requests_mutex.Unlock()
	if nil != cached {
		cached.timestamp = time.Now().Unix()
		return cached
	}
	return &clientRequest{c: make(chan *clientRequest, 1), timestamp: time.Now().Unix()}
}

func releaseRequest(will_cache *clientRequest) {
	will_cache.request = nil
	will_cache.response = nil
	will_cache.timeout = default_timeout
	will_cache.e = nil
	will_cache.cb = nil

	requests_mutex.Lock()
	requests_cache.Push(will_cache)
	requests_mutex.Unlock()
}

type bytesRequest struct {
	cached []byte
	length int
}

type UdpClient struct {
	DEBUG, ERROR  Writer
	is_closed     int32
	wait          sync.WaitGroup
	client_c      chan *clientRequest
	bytes_c       chan bytesRequest
	next_id       int
	host          string
	logCtx        string
	poll_interval time.Duration
	engine        snmpEngine
	conn          *net.UDPConn
	conn_ok       int32
	pendings      map[int]*clientRequest

	lastAt         time.Time
	is_expired     int32
	cached_deleted []int

	cached_rlock      sync.Mutex
	conn_error        error
	cached_writeBytes []byte
	cached_readBytes  []byte
}

func NewSnmpClient(host string) (Client, SnmpError) {
	return NewSnmpClientWith(host, 1*time.Second, &NullWriter{}, &LogWriter{})
}

func NewSnmpClientWith(host string, poll_interval time.Duration, debugWriter, errorWriter Writer) (Client, SnmpError) {
	client := &UdpClient{host: NormalizeAddress(host),
		poll_interval:  poll_interval,
		lastAt:         time.Now(),
		is_expired:     1,
		cached_deleted: make([]int, 256),
		client_c:       make(chan *clientRequest),
		bytes_c:        make(chan bytesRequest, 100)}

	client.logCtx = "[snmpclient-" + client.host + "]"
	client.pendings = make(map[int]*clientRequest)
	client.DEBUG = debugWriter
	client.ERROR = errorWriter

	if client.engine.max_msg_size <= 0 {
		client.engine.max_msg_size = uint(*maxPDUSize)
	}

	client.cached_writeBytes = make([]byte, int(client.engine.max_msg_size))

	go client.serve()
	client.wait.Add(1)
	return client, nil
}

func (client *UdpClient) Close() {
	if !atomic.CompareAndSwapInt32(&client.is_closed, 0, 1) {
		return
	}

	close(client.client_c)
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
			client.ERROR.Print(client.logCtx, buffer.String())
		}
		atomic.StoreInt32(&client.is_closed, 1)
		client.wait.Done()
	}()

	defer func() {
		client.onDisconnection(errors.New("client is closed"))

		client.disconnect()
	}()

	ticker := time.NewTicker(client.poll_interval)
	defer ticker.Stop()

	is_running := true
	for is_running {
		select {
		case request, ok := <-client.client_c:
			if !ok {
				is_running = false
				break
			}
			client.executeRequest(request)
		case data := <-client.bytes_c:
			client.handleRecv(data.cached[:data.length])
			client.cached_rlock.Lock()
			client.cached_readBytes = data.cached
			client.cached_rlock.Unlock()
		case <-ticker.C:
			client.fireTick()
		}
	}
}

func (client *UdpClient) fireTick() {
	now := time.Now()
	if now.After(client.lastAt.Add(time.Duration(*deadTimeout) * time.Minute)) {
		atomic.StoreInt32(&client.is_expired, 0)
	} else {
		atomic.StoreInt32(&client.is_expired, 1)
	}

	if 1 != atomic.LoadInt32(&client.conn_ok) {
		client.onDisconnection(nil)
	} else {
		now_seconds := now.Unix()
		deleted := client.cached_deleted
		for id, cr := range client.pendings {
			if (now_seconds - int64(cr.timeout.Seconds())) > cr.timestamp {
				deleted = append(deleted, id)
				cr.reply(nil, TimeoutError)
			}
		}

		for _, id := range deleted {
			delete(client.pendings, id)
		}
	}
}

func (client *UdpClient) executeRequest(request *clientRequest) {
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
			msg := buffer.String()
			request.reply(nil, Error(SNMP_CODE_FAILED, msg))
			client.DEBUG.Print(msg)
		}
	}()

	client.handleSend(request, request.request)
}

func (client *UdpClient) Stats() interface{} {
	return map[string]interface{}{"pendings_requests": len(client.pendings), "queue": len(client.client_c)}
}

func (client *UdpClient) IsExpired() bool {
	return 0 == atomic.LoadInt32(&client.is_expired)
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

func (client *UdpClient) SendAndRecv(request PDU, timeout time.Duration) (response PDU, e SnmpError) {
	if timeout > 1*time.Minute {
		timeout = 1 * time.Minute
	} else if timeout < 1*time.Second {
		timeout = 1 * time.Second
	}

	cr := newRequest()
	cr.request = request
	cr.timeout = timeout
	client.client_c <- cr

	res := <-cr.c
	response = res.response
	e = res.e
	releaseRequest(res)
	return response, e
}

func (client *UdpClient) sendV3PDU(request *clientRequest, pdu *V3PDU, autoDiscoverEngine bool) {
	if nil == pdu.securityModel {
		request.reply(nil, Error(SNMP_CODE_FAILED, "securityModel is nil"))
		return
	}

	if !pdu.securityModel.IsLocalize() {
		if nil == pdu.engine {
			if client.DEBUG.IsEnabled() {
				client.DEBUG.Printf("snmp - send failed, nil == pdu.engine, " + pdu.String())
			}
			request.reply(nil, Error(SNMP_CODE_FAILED, "nil == pdu.engine"))
			return
		}
		pdu.securityModel.Localize(pdu.engine.engine_id)
	}

	if autoDiscoverEngine {
		request.cb = func(resp PDU, err SnmpError) {
			request.cb = nil

			if nil != err {
				switch err.Code() {
				case SNMP_CODE_NOTINTIME, SNMP_CODE_BADENGINE:

					if nil != pdu.engine {
						pdu.engine.engine_id = nil
					}
					client.engine.engine_id = nil
					client.discoverEngineAndSend(request, pdu)
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

			request.reply(resp, err)
		}
	}
	client.sendPdu(pdu, request)
}

func (client *UdpClient) discoverEngine(fn func(PDU, SnmpError)) {
	if client.DEBUG.IsEnabled() {
		client.DEBUG.Printf("snmp - discover snmp engine")
	}

	usm := &USM{auth_proto: SNMP_AUTH_NOAUTH, priv_proto: SNMP_PRIV_NOPRIV}
	pdu := &V3PDU{op: SNMP_PDU_GET, securityModel: usm}
	request := newRequest()
	request.request = pdu
	request.cb = fn
	client.sendPdu(pdu, request)
}

func (client *UdpClient) discoverEngineAndSend(request *clientRequest, pdu *V3PDU) {
	if nil != pdu.engine && nil != pdu.engine.engine_id && 0 != len(pdu.engine.engine_id) {
		client.sendV3PDU(request, pdu, false)
		return
	}

	if nil != client.engine.engine_id && 0 != len(client.engine.engine_id) {
		if nil == pdu.engine {
			pdu.engine = &client.engine
		} else {
			pdu.engine.CopyFrom(&client.engine)
		}
		client.sendV3PDU(request, pdu, true)
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
			request.reply(nil, err)
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

			request.reply(nil, err)
			return
		}

		client.engine.CopyFrom(v3.engine)
		if nil == pdu.engine {
			pdu.engine = &client.engine
		} else {
			pdu.engine.engine_id = client.engine.engine_id
		}

		client.sendV3PDU(request, pdu, false)
	})
}

func (client *UdpClient) connect() SnmpError {
	if nil != client.conn {
		if 1 == atomic.LoadInt32(&client.conn_ok) {
			return nil
		}
		client.conn.Close()
		client.conn = nil
		client.onDisconnection(nil)
	}

	addr, err := net.ResolveUDPAddr("udp", client.host)
	if nil != err {
		return newError(SNMP_CODE_FAILED, err, "parse address failed")
	}
	client.conn, err = net.DialUDP("udp", nil, addr)
	if nil != err {
		return newError(SNMP_CODE_FAILED, err, "bind udp port failed")
	}

	atomic.StoreInt32(&client.conn_ok, 1)
	go client.readUDP(client.conn)
	return nil
}

func (client *UdpClient) disconnect() {
	defer func() {
		client.conn = nil
		if err := recover(); nil != err {
			client.DEBUG.Print(client.logCtx, err)
		}
	}()
	if nil != client.conn {
		client.conn.Close()
		client.conn = nil
	}
}

// FIXME:  注意 conn 对象被多个goroutine 持有了，
func (client *UdpClient) readUDP(conn *net.UDPConn) {
	var err error

	defer func() {
		if err := recover(); nil != err {
			client.ERROR.Print("[panic]", client.logCtx, " read udp failed,", err)
		}
		conn.Close()
		atomic.StoreInt32(&client.conn_ok, 0)
	}()

	for 0 == atomic.LoadInt32(&client.is_closed) {
		var length int
		var bs []byte

		client.cached_rlock.Lock()
		bs = client.cached_readBytes
		client.cached_readBytes = nil
		client.cached_rlock.Unlock()
		if nil == bs {
			bs = make([]byte, *maxPDUSize)
		}

		length, err = conn.Read(bs)
		if 0 != atomic.LoadInt32(&client.is_closed) {
			break
		}

		if nil != err {
			client.cached_rlock.Lock()
			client.conn_error = err
			client.cached_rlock.Unlock()
			client.ERROR.Print(client.logCtx, "read udp from conn failed", err)
			break
		}

		if client.DEBUG.IsEnabled() {
			client.DEBUG.Printf("snmp - read ok")
			client.DEBUG.Print(hex.EncodeToString(bs[:length]))
		}

		client.bytes_c <- bytesRequest{cached: bs, length: length}
	}

	client.ERROR.Print(client.logCtx, "read udp is exited.")
}

func (client *UdpClient) onDisconnection(err error) {
	if nil == err {
		client.cached_rlock.Lock()
		err = client.conn_error
		client.cached_rlock.Unlock()
		if nil == err {
			err = disconnectError
		}
	}

	e := newError(SNMP_CODE_BADNET, err, "read from '"+client.host+"' failed")

	for _, req := range client.pendings {
		req.reply(nil, e)
	}
	client.pendings = make(map[int]*clientRequest)
}

func (client *UdpClient) handleRecv(bytes []byte) {
	var buffer C.asn_buf_t
	var pdu C.snmp_pdu_t
	var result PDU
	var req *clientRequest
	var ok bool

	C.set_asn_u_ptr(&buffer.asn_u, (*C.char)(unsafe.Pointer(&bytes[0])))
	buffer.asn_len = C.size_t(len(bytes))

	err := DecodePDUHeader(&buffer, &pdu)
	if nil != err {
		client.ERROR.Print(client.logCtx, "decode head of pdu failed", err)
		return
	}
	defer C.snmp_pdu_free(&pdu)

	if uint32(SNMP_V3) == pdu.version {
		req, ok = client.pendings[int(pdu.identifier)]
		if !ok {
			client.ERROR.Print(client.logCtx, "request with requestId was ", int(pdu.identifier), " or ", int(pdu.request_id), " is not exists.")

			// for i, _ := range client.pendings {
			// 	client.ERROR.Print(i)
			// }
			return
		}
		delete(client.pendings, int(pdu.identifier))

		v3old, ok := req.request.(*V3PDU)
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
			client.ERROR.Print(client.logCtx, "fill user information failed,", err.Error())
			goto complete
		}

		err = DecodePDUBody(&buffer, &pdu)
		if nil != err {
			client.ERROR.Print(client.logCtx, "decode body of pdu failed", err.Error())
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
			client.ERROR.Print(client.logCtx, "decode body of pdu failed", err.Error())
			return
		}

		req, ok = client.pendings[int(pdu.request_id)]
		if !ok {
			client.ERROR.Print(client.logCtx, "request with requestId was", int(pdu.request_id), "is not exists.")
			return
		}
		delete(client.pendings, int(pdu.request_id))

		if client.DEBUG.IsEnabled() {
			C.snmp_pdu_dump(&pdu)
		}

		v2 := &V2CPDU{}
		_, err = v2.decodePDU(&pdu)
		result = v2
	}

complete:
	req.reply(result, err)
}

func (client *UdpClient) handleSend(reply *clientRequest, pdu PDU) {
	client.lastAt = time.Now()

	var err error
	err = client.connect()
	if nil != err {
		goto failed
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

	client.ERROR.Print(client.logCtx, "snmp - send failed, ", err, " - ", pdu)

	reply.reply(nil, toSnmpCodeError(err))
	return
}

func (client *UdpClient) sendPdu(pdu PDU, callback *clientRequest) {
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
		goto failed_no_remove_pendings
	}

	bytes, err = EncodePDU(pdu, client.cached_writeBytes, client.DEBUG.IsEnabled())
	if nil != err {
		err = newError(err.Code(), err, "encode pdu failed")
		goto failed
	}

	client.pendings[pdu.GetRequestID()] = callback

	_, e = client.conn.Write(bytes)
	if nil != e {
		client.disconnect()
		err = newError(SNMP_CODE_BADNET, e, "send pdu failed")
		client.onDisconnection(err)
		goto failed
	}

	if client.DEBUG.IsEnabled() {
		client.DEBUG.Print("snmp - send success, " + pdu.String())
		client.DEBUG.Print(hex.EncodeToString(bytes))
	}

	return

failed:
	delete(client.pendings, pdu.GetRequestID())
failed_no_remove_pendings:
	if client.ERROR.IsEnabled() {
		client.ERROR.Print(client.logCtx, "snmp - send failed, ", err, ", ", pdu)
	}

	callback.reply(nil, err)
	return
}

func (client *UdpClient) FreePDU(pdus ...PDU) {

}
