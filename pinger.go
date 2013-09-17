// Copyright 2009 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snmpclient

// #include "bsnmp/config.h"
// #include "bsnmp/asn1.h"
// #include "bsnmp/snmp.h"
// #include "bsnmp/gobindings.h"
import "C"
import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var TimeoutError = errors.New("time out")

type PingResult struct {
	Id             int
	Addr           net.Addr
	Version        SnmpVersion
	Community      string
	SecurityParams map[string]string
	Error          error
	Timestamp      time.Time
}

type internal_pinger struct {
	network        string
	id             int
	version        SnmpVersion
	community      string
	securityParams map[string]string
	conn           net.PacketConn
	wait           *sync.WaitGroup
	ch             chan *PingResult
	is_running     int32
	cached_bytes   []byte
}

// make(chan *PingResult, capacity)
func newpinger(network, laddr string, wait *sync.WaitGroup, ch chan *PingResult, version SnmpVersion, community string,
	securityParams map[string]string) (*internal_pinger, error) {
	c, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, fmt.Errorf("ListenPacket(%q, %q) failed: %v", network, laddr, err)
	}
	internal_pinger := &internal_pinger{network: network,
		id:             1,
		wait:           wait,
		conn:           c,
		ch:             ch,
		version:        version,
		community:      community,
		securityParams: securityParams,
		is_running:     1}

	go internal_pinger.serve()
	internal_pinger.wait.Add(1)
	return internal_pinger, nil
}

// func Newpinger(network, laddr string, ch chan *PingResult, version SnmpVersion, community string) (*internal_pinger, error) {
// 	return newpinger(network, laddr, ch, version, community, nil)
// }

// func NewV3pinger(network, laddr string, ch chan *PingResult, securityParams map[string]string) (*internal_pinger, error) {
// 	return newpinger(network, laddr, ch, SNMP_V3, "", securityParams)
// }

func (self *internal_pinger) closeIO() {
	atomic.StoreInt32(&self.is_running, 0)
	self.conn.Close()
}

func (self *internal_pinger) Close() {
	self.closeIO()
	self.wait.Wait()
	close(self.ch)
}

func (self *internal_pinger) GetChannel() <-chan *PingResult {
	return self.ch
}

var emptyParams = map[string]string{}

func (self *internal_pinger) Send(raddr string) error {
	ra, err := net.ResolveUDPAddr(self.network, raddr)
	if err != nil {
		return fmt.Errorf("ResolveIPAddr(%q, %q) failed: %v", self.network, raddr, err)
	}
	return self.SendPdu(0, raddr, ra, self.version, self.community, self.securityParams)
}

func (self *internal_pinger) SendPdu(id int, raddr string, ra *net.UDPAddr, version SnmpVersion, community string, securityParams map[string]string) error {
	if 0 == id {
		self.id++
		id = self.id
	}

	var pdu PDU = nil
	switch version {
	case SNMP_V1, SNMP_V2C:
		pdu = &V2CPDU{op: SNMP_PDU_GET, version: version, requestId: id, target: raddr, community: community}
		pdu.Init(emptyParams)
		err := pdu.GetVariableBindings().Append("1.3.6.1.2.1.1.2.0", "")
		if err != nil {
			return fmt.Errorf("AppendVariableBinding failed: %v", err)
		}
	case SNMP_V3:
		pdu = &V3PDU{op: SNMP_PDU_GET, requestId: id, identifier: id, target: raddr,
			securityModel: &USM{auth_proto: SNMP_AUTH_NOAUTH, priv_proto: SNMP_PRIV_NOPRIV}}
		pdu.Init(emptyParams)
	default:
		return fmt.Errorf("Unsupported version - %v", version)
	}

	if nil == self.cached_bytes {
		self.cached_bytes = make([]byte, 1024)
	}

	bytes, e := EncodePDU(pdu, self.cached_bytes, false)
	if e != nil {
		return fmt.Errorf("EncodePDU failed: %v", e)
	}
	l, err := self.conn.WriteTo(bytes, ra)
	if err != nil {
		return fmt.Errorf("WriteTo failed: %v", err)
	}
	if l == 0 {
		return fmt.Errorf("WriteTo failed: wlen == 0")
	}
	return nil
}

func (self *internal_pinger) Recv(timeout time.Duration) (net.Addr, SnmpVersion, error) {
	select {
	case res := <-self.ch:
		return res.Addr, res.Version, res.Error
	case <-time.After(timeout):
		return nil, SNMP_Verr, TimeoutError
	}
	return nil, SNMP_Verr, TimeoutError
}

func (self *internal_pinger) serve() {
	defer self.wait.Done()

	reply := make([]byte, 2048)
	var buffer C.asn_buf_t
	var pdu C.snmp_pdu_t

	for 1 == atomic.LoadInt32(&self.is_running) {
		l, ra, err := self.conn.ReadFrom(reply)
		if err != nil {
			if strings.Contains(err.Error(), "No service is operating") { //Port Unreachable
				continue
			}
			if strings.Contains(err.Error(), "forcibly closed by the remote host") { //Port Unreachable
				continue
			}
			self.ch <- &PingResult{Error: fmt.Errorf("ReadFrom failed: %v, %v", ra, err)}
			continue
		}

		C.set_asn_u_ptr(&buffer.asn_u, (*C.char)(unsafe.Pointer(&reply[0])))
		buffer.asn_len = C.size_t(l)

		err = DecodePDUHeader(&buffer, &pdu)
		if nil != err {
			self.ch <- &PingResult{Error: fmt.Errorf("Parse Data failed: %s %v", ra.String(), err)}
			continue
		}
		ver := SNMP_Verr
		id := 0
		//community := ""
		switch pdu.version {
		case uint32(SNMP_V3):
			ver = SNMP_V3
			id = int(pdu.identifier)
		case uint32(SNMP_V2C):
			ver = SNMP_V2C
			err = DecodePDUBody(&buffer, &pdu)
			if nil == err {
				id = int(pdu.request_id)
			}
			//community = C.GoString(pdu.community)
		case uint32(SNMP_V1):
			ver = SNMP_V1
			err = DecodePDUBody(&buffer, &pdu)
			if nil == err {
				id = int(pdu.request_id)
			}
			//community = C.GoString(pdu.community)
		}
		// if 0 == len(community) {
		// 	community = self.community
		// }
		self.ch <- &PingResult{Id: id, Addr: ra, Version: ver, Community: self.community, SecurityParams: self.securityParams, Timestamp: time.Now()}
		C.snmp_pdu_free(&pdu)
	}
}

type Pingers struct {
	internals []*internal_pinger
	ch        chan *PingResult
	wait      sync.WaitGroup
}

func NewPingers(capacity int) *Pingers {
	return &Pingers{internals: make([]*internal_pinger, 0, 10), ch: make(chan *PingResult, capacity)}
}

func (self *Pingers) Listen(network, laddr string, version SnmpVersion, community string) error {
	p, e := newpinger(network, laddr, &self.wait, self.ch, version, community, nil)
	if nil != e {
		return e
	}
	self.internals = append(self.internals, p)
	return nil
}

func (self *Pingers) ListenV3(network, laddr string, securityParams map[string]string) error {
	p, e := newpinger(network, laddr, &self.wait, self.ch, SNMP_V3, "", securityParams)
	if nil != e {
		return e
	}
	self.internals = append(self.internals, p)
	return nil
}

func (self *Pingers) Close() {
	for _, p := range self.internals {
		p.closeIO()
	}
	self.wait.Wait()
	close(self.ch)
}

func (self *Pingers) GetChannel() <-chan *PingResult {
	return self.ch
}

func (self *Pingers) Length() int {
	return len(self.internals)
}

func (self *Pingers) Send(idx int, raddr string) error {
	return self.internals[idx].Send(raddr)
}

func (self *Pingers) Recv(timeout time.Duration) (net.Addr, SnmpVersion, error) {
	select {
	case res := <-self.ch:
		return res.Addr, res.Version, res.Error
	case <-time.After(timeout):
		return nil, SNMP_Verr, TimeoutError
	}
	return nil, SNMP_Verr, TimeoutError
}

type Pinger struct {
	internal *internal_pinger
	ch       chan *PingResult
	wait     sync.WaitGroup
}

func NewPinger(network, laddr string, capacity int) (*Pinger, error) {
	self := &Pinger{}
	self.ch = make(chan *PingResult, capacity)
	p, e := newpinger(network, laddr, &self.wait, self.ch, SNMP_V2C, "public", emptyParams)
	if nil != e {
		return nil, e
	}
	self.internal = p
	return self, nil
}

func (self *Pinger) Close() {
	if nil == self {
		return
	}
	if nil != self.internal {
		self.internal.closeIO()
		self.wait.Wait()
		close(self.ch)
	}
}

func (self *Pinger) GetChannel() <-chan *PingResult {
	return self.ch
}

func (self *Pinger) SendPdu(id int, raddr string, ra *net.UDPAddr, version SnmpVersion, community string) error {
	return self.internal.SendPdu(id, raddr, ra, version, community, nil)
}

func (self *Pinger) Send(id int, raddr string, version SnmpVersion, community string) error {
	ra, err := net.ResolveUDPAddr(self.internal.network, raddr)
	if err != nil {
		return fmt.Errorf("ResolveIPAddr(%q, %q) failed: %v", self.internal.network, raddr, err)
	}

	return self.internal.SendPdu(id, raddr, ra, version, community, nil)
}

func (self *Pinger) SendV3(id int, raddr string, securityParams map[string]string) error {
	ra, err := net.ResolveUDPAddr(self.internal.network, raddr)
	if err != nil {
		return fmt.Errorf("ResolveIPAddr(%q, %q) failed: %v", self.internal.network, raddr, err)
	}

	return self.internal.SendPdu(id, raddr, ra, SNMP_V3, "", securityParams)
}

func (self *Pinger) Recv(timeout time.Duration) (net.Addr, SnmpVersion, error) {
	select {
	case res := <-self.ch:
		return res.Addr, res.Version, res.Error
	case <-time.After(timeout):
		return nil, SNMP_Verr, TimeoutError
	}
	return nil, SNMP_Verr, TimeoutError
}
