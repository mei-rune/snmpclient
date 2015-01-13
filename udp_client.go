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
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	maxPDUSize  = flag.Uint("maxPDUSize", 20480, "set max size of pdu")
	deadTimeout = flag.Int("deadTimeout", 1, "set timeout(Minute) of client to dead")

	snmp_agents_by_listen = flag.String("snmp_agents_by_listen_mode", "", "use listen mode for the snmp agents.")
	disconnectError       = errors.New("connection is disconnected.")

	all_snmp_agents_by_listen = map[string]string{}

	use_listen_mode = flag.Bool("use_listen_mode", false, "use listen mode.")
)

const (
	PDU_MAX_RID int32 = 32767 ///< max request id to use
	PDU_MIN_RID int32 = 1000  ///< min request id to use
)

func init() {
	ip_list := strings.Split(*snmp_agents_by_listen, ",")
	if 0 == len(ip_list) {
		for _, ip := range ip_list {
			all_snmp_agents_by_listen[ip] = ip
		}
	}

	ip_list = strings.Split(os.Getenv("snmp_agents_by_listen_mode"), ",")
	if 0 == len(ip_list) {
		for _, ip := range ip_list {
			all_snmp_agents_by_listen[ip] = ip
		}
	}
}

func UseListenModeAll() {
	flag.Set("use_listen_mode", "true")
}

func NotUseListenModeAll() {
	flag.Set("use_listen_mode", "false")
}

func UseListenMode(ip string) {
	if strings.HasPrefix(ip, "[") {
		if idx := strings.IndexRune(ip, ']'); 0 > idx {
			ip = ip[:idx+1]
		}
	} else if idx := strings.IndexRune(ip, ':'); 0 > idx {
		ip = ip[:idx]
	}
	all_snmp_agents_by_listen[ip] = ip
}

func NotUseListenMode(ip string) {
	if strings.HasPrefix(ip, "[") {
		if idx := strings.IndexRune(ip, ']'); 0 > idx {
			ip = ip[:idx+1]
		}
	} else if idx := strings.IndexRune(ip, ':'); 0 > idx {
		ip = ip[:idx]
	}
	delete(all_snmp_agents_by_listen, ip)
}

// type clientReply interface {
// 	reply(pdu PDU, e SnmpError)
// }

type clientRequest struct {
	c            chan *clientRequest
	timestamp    int64
	timeout      time.Duration
	resend_count int64
	request      PDU
	response     PDU
	e            SnmpError
	cb           func(pdu PDU, e SnmpError)
}

func (cr *clientRequest) resend(client *UdpClient) error {
	return client.resendPdu(cr.request)
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

	bytes_mutex sync.Mutex
	bytes_cache = newBytesBuffer(make([][]byte, 10))
)

func init() {
	expvar.Publish("snmp_request_cache", expvar.Func(func() interface{} {
		requests_mutex.Lock()
		size := requests_cache.Size()
		requests_mutex.Unlock()
		return size
	}))

	expvar.Publish("snmp_bytes_cache", expvar.Func(func() interface{} {
		bytes_mutex.Lock()
		size := bytes_cache.Size()
		bytes_mutex.Unlock()
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
	will_cache.timeout = 0
	will_cache.resend_count = 0
	will_cache.e = nil
	will_cache.cb = nil

	requests_mutex.Lock()
	requests_cache.Push(will_cache)
	requests_mutex.Unlock()
}

func newCachedBytes() []byte {
	bytes_mutex.Lock()
	cached := bytes_cache.Pop()
	bytes_mutex.Unlock()
	if nil != cached {
		return cached
	}
	return make([]byte, *maxPDUSize)
}

func releaseCachedBytes(will_cache []byte) {
	bytes_mutex.Lock()
	bytes_cache.Push(will_cache)
	bytes_mutex.Unlock()
}

type bytesRequest struct {
	cached []byte
	length int
}

type UdpClient struct {
	DEBUG, ERROR     Writer
	is_closed        int32
	wait             sync.WaitGroup
	client_c         chan *clientRequest
	bytes_c          chan bytesRequest
	next_id          int32
	is_listen_mode   bool
	host             string
	logCtx           string
	peer_addr        net.UDPAddr
	expired_interval time.Duration
	poll_interval    time.Duration
	engine           snmpEngine
	conn             *net.UDPConn
	conn_ok          int32
	pendings         map[int]*clientRequest

	lastAt         time.Time
	is_expired     int32
	cached_deleted []int

	cached_rlock      sync.Mutex
	conn_error        error
	cached_writeBytes []byte
	cached_readBytes  []byte
}

func NewSnmpClient(host string) (Client, SnmpError) {
	return NewSnmpClientWith(host, 1*time.Second, time.Duration(*deadTimeout)*time.Minute, &NullWriter{}, &LogWriter{})
}

func NewSnmpClientWith(host string, poll_interval, expired_interval time.Duration, debugWriter, errorWriter Writer) (Client, SnmpError) {
	client := &UdpClient{host: NormalizeAddress(host),
		poll_interval:    poll_interval,
		expired_interval: expired_interval,
		lastAt:           time.Now(),
		is_expired:       0,
		next_id:          PDU_MIN_RID,
		cached_deleted:   make([]int, 0, 256),
		client_c:         make(chan *clientRequest),
		bytes_c:          make(chan bytesRequest, 100)}

	client.logCtx = "[snmpclient-" + client.host + "]"
	client.pendings = make(map[int]*clientRequest)
	client.DEBUG = debugWriter
	client.ERROR = errorWriter

	if client.engine.max_msg_size <= 0 {
		client.engine.max_msg_size = uint(*maxPDUSize)
	}

	addr, err := net.ResolveUDPAddr("udp", client.host)
	if nil != err {
		return nil, newError(SNMP_CODE_FAILED, err, "parse address failed")
	}
	client.peer_addr = *addr

	if *use_listen_mode {
		client.is_listen_mode = true
	} else if _, ok := all_snmp_agents_by_listen[client.peer_addr.IP.String()]; ok {
		client.is_listen_mode = true
	}

	client.cached_writeBytes = make([]byte, int(client.engine.max_msg_size))

	go client.serve()
	client.wait.Add(1)
	return client, nil
}

func (client *UdpClient) UseListenMode() {
	client.is_listen_mode = true
}

func (client *UdpClient) SetNextId(next_id int32) {
	client.next_id = next_id
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

		if atomic.CompareAndSwapInt32(&client.is_closed, 0, 1) {
			close(client.client_c)
		}
		atomic.StoreInt32(&client.is_expired, 1)
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
			if nil != client.cached_readBytes {
				client.cached_rlock.Unlock()
				releaseCachedBytes(data.cached)
			} else {
				client.cached_readBytes = data.cached
				client.cached_rlock.Unlock()
			}
		case <-ticker.C:
			client.fireTick()
		}
	}
}

func (client *UdpClient) fireTick() {
	now := time.Now()
	if now.After(client.lastAt.Add(client.expired_interval)) {
		atomic.StoreInt32(&client.is_expired, 1)
	} else {
		atomic.StoreInt32(&client.is_expired, 0)
	}

	if 1 != atomic.LoadInt32(&client.conn_ok) {
		client.onDisconnection(nil)
	} else {
		now_seconds := now.Unix()
		deleted := client.cached_deleted[0:0]
		for id, cr := range client.pendings {
			t := now_seconds - cr.timestamp
			if t > int64(cr.timeout.Seconds()) {
				deleted = append(deleted, id)
				cr.reply(nil, TimeoutError)
			} else if t >= 10 {
				if client.poll_interval < 5*time.Second {
					if t < cr.resend_count*5 {
						continue
					}
				}
				if e := cr.resend(client); nil != e {
					client.DEBUG.Print(client.logCtx, "resend pdu failed, "+e.Error()+"\r\n"+cr.request.String())
				}

				cr.resend_count++
			}
		}

		for _, id := range deleted {
			delete(client.pendings, id)
		}
	}
}

func safesend(r *clientRequest, e SnmpError) {
	defer func() {
		recover()
	}()
	r.reply(nil, e)
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
			safesend(request, Error(SNMP_CODE_FAILED, msg))
			client.DEBUG.Print(client.logCtx, msg)
		}
	}()

	client.handleSend(request, request.request)
}

func (client *UdpClient) Stats() interface{} {
	return map[string]interface{}{"id": client.logCtx, "pendings_requests": len(client.pendings), "queue": len(client.client_c)}
}

func (client *UdpClient) IsExpired() bool {
	return 1 == atomic.LoadInt32(&client.is_expired)
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
	} else if 0 >= timeout {
		timeout = 30 * time.Second
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
	if nil == e {
		releaseRequest(res)
	} // else {
	//	close(cr.c) // ensure send result failed while timeout is first.
	//}
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
				client.DEBUG.Print(client.logCtx, "send pdu failed, nil == pdu.engine, "+pdu.String())
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
					client.DEBUG.Print(client.logCtx, "[snmpv3] - recv pdu failed,", err)
				} else {
					client.DEBUG.Print(client.logCtx, "[snmpv3] - recv pdu success,", resp)
				}
			}

			request.reply(resp, err)
		}
	}
	client.sendPdu(pdu, request)
}

func (client *UdpClient) discoverEngine(fn func(PDU, SnmpError)) {
	if client.DEBUG.IsEnabled() {
		client.DEBUG.Print(client.logCtx, "discover snmp engine")
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
				client.DEBUG.Print(client.logCtx, "recv pdu, ", err.Error())
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
				client.DEBUG.Print(client.logCtx, "recv pdu,", err.Error())
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
	var err error
	if client.is_listen_mode {
		client.conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	} else {
		client.conn, err = net.DialUDP("udp", nil, &client.peer_addr)
	}
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
		if o := recover(); nil != o {
			client.DEBUG.Print(client.logCtx, "[panic] failed to close the udp connection,", o)
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
			bs = newCachedBytes()
		}

		if client.DEBUG.IsEnabled() {
			client.DEBUG.Print(client.logCtx, "begin read pdu - ", len(bs))
		}
		length, err = conn.Read(bs)
		if 0 != atomic.LoadInt32(&client.is_closed) {
			break
		}
		if 10 > length {
			continue
		}

		if nil != err {
			client.cached_rlock.Lock()
			client.conn_error = err
			client.cached_rlock.Unlock()
			client.ERROR.Print(client.logCtx, "read udp from conn failed", err)
			break
		}

		if client.DEBUG.IsEnabled() {
			client.DEBUG.Print(client.logCtx, "read pdu ok - ", hex.EncodeToString(bs[:length]))
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

func (client *UdpClient) handleRecv(recv_bytes []byte) {
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
	}()

	var buffer C.asn_buf_t
	var result PDU
	var req *clientRequest
	var ok bool

	internal := newNativePdu()
	C.snmp_pdu_init(internal)
	defer releaseNativePdu(internal)

	C.set_asn_u_ptr(&buffer.asn_u, (*C.char)(unsafe.Pointer(&recv_bytes[0])))
	buffer.asn_len = C.size_t(len(recv_bytes))

	err := DecodePDUHeader(&buffer, internal)
	if nil != err {
		client.ERROR.Print(client.logCtx, "decode head of pdu failed", err)
		return
	}
	defer C.snmp_pdu_free(internal)

	if uint32(SNMP_V3) == internal.version {
		req, ok = client.pendings[int(internal.identifier)]
		if !ok {
			client.ERROR.Print(client.logCtx, "request with requestId was ", int(internal.identifier), " or ", int(internal.request_id), " is not exists.")

			// for i, _ := range client.pendings {
			// 	client.ERROR.Print(i)
			// }
			return
		}
		delete(client.pendings, int(internal.identifier))

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
		err = FillUser(internal, usm.auth_proto, usm.localization_auth_key,
			usm.priv_proto, usm.localization_priv_key)
		if nil != err {
			client.ERROR.Print(client.logCtx, "fill user information failed,", err.Error())
			goto complete
		}

		err, ok = DecodePDUBody2(&buffer, internal)
		if nil != err {
			client.ERROR.Print(client.logCtx, "decode body of pdu failed", err.Error())
			goto complete
		}
		if ok {
			client.ERROR.Print(client.logCtx, "ignored some error", hex.EncodeToString(recv_bytes))
		}

		if client.DEBUG.IsEnabled() {
			C.snmp_pdu_dump(internal)
		}

		var v3 V3PDU
		_, err = v3.decodePDU(internal)
		result = &v3
	} else {
		err, ok = DecodePDUBody2(&buffer, internal)
		if nil != err {
			client.ERROR.Print(client.logCtx, "decode body of pdu failed", err.Error())
			return
		}

		if ok {
			client.ERROR.Print(client.logCtx, "ignored some error", hex.EncodeToString(recv_bytes))
		}

		req, ok = client.pendings[int(internal.request_id)]
		if !ok {
			client.ERROR.Print(client.logCtx, "request with requestId was", int(internal.request_id), "is not exists.")
			return
		}
		delete(client.pendings, int(internal.request_id))

		if client.DEBUG.IsEnabled() {
			C.snmp_pdu_dump(internal)
		}

		v2 := &V2CPDU{}
		_, err = v2.decodePDU(internal)
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

	client.ERROR.Print(client.logCtx, "send pdu failed, ", err, " - ", pdu)

	reply.reply(nil, toSnmpCodeError(err))
	return
}

func (client *UdpClient) sendPdu(pdu PDU, callback *clientRequest) {
	if nil == callback {
		panic("'callback' is nil")
	}

	var send_bytes []byte = nil
	var err SnmpError = nil
	var e error = nil
	client.next_id++
	if client.next_id > PDU_MAX_RID {
		client.next_id = PDU_MIN_RID + 1
	}
	pdu.SetRequestID(int(client.next_id))

	_, ok := client.pendings[pdu.GetRequestID()]
	if ok {
		err = Error(SNMP_CODE_FAILED, "identifier of pdu is repected.")
		goto failed_no_remove_pendings
	}

	send_bytes, err = EncodePDU(pdu, client.cached_writeBytes, client.DEBUG.IsEnabled())
	if nil != err {
		err = newError(err.Code(), err, "encode pdu failed")
		goto failed
	}

	client.pendings[pdu.GetRequestID()] = callback

	if client.is_listen_mode {
		_, e = client.conn.WriteToUDP(send_bytes, &client.peer_addr)
	} else {
		_, e = client.conn.Write(send_bytes)
	}
	if nil != e {
		client.disconnect()
		err = newError(SNMP_CODE_BADNET, e, "send pdu failed")
		client.onDisconnection(err)
		goto failed
	}

	if client.DEBUG.IsEnabled() {
		client.DEBUG.Print(client.logCtx, "send pdu success,", pdu.String(), "--", hex.EncodeToString(send_bytes))
	}

	return

failed:
	delete(client.pendings, pdu.GetRequestID())
failed_no_remove_pendings:
	if client.ERROR.IsEnabled() {
		client.ERROR.Print(client.logCtx, "send pdu failed, ", err, ", ", pdu)
	}

	callback.reply(nil, err)
	return
}

func (client *UdpClient) resendPdu(pdu PDU) error {
	var send_bytes []byte = nil
	var err SnmpError = nil
	var e error = nil
	if nil == client.conn {
		return nil
	}

	send_bytes, err = EncodePDU(pdu, client.cached_writeBytes, client.DEBUG.IsEnabled())
	if nil != err {
		return err
	}

	_, e = client.conn.Write(send_bytes)
	if nil != e {
		client.disconnect()
		err = newError(SNMP_CODE_BADNET, e, "send pdu failed")
		client.onDisconnection(err)
		return e
	}

	return nil
}

func (client *UdpClient) FreePDU(pdus ...PDU) {

}
