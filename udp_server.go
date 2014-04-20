package snmpclient

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

type OidAndValue struct {
	Oid   SnmpOid
	Value SnmpValue
}

func compareOidAdValue(a1, b1 Item) int {
	a, ok := a1.(SnmpOid)
	if !ok {
		v, ok := a1.(*OidAndValue)
		if !ok {
			panic("a1 is not OidAndValue")
		}
		a = v.Oid
	}

	b, ok := b1.(SnmpOid)
	if !ok {
		v, ok := b1.(*OidAndValue)
		if !ok {
			panic("b1 is not OidAndValue")
		}
		b = v.Oid
	}

	a_uint32s := a.GetUint32s()
	b_uint32s := b.GetUint32s()
	for idx, c := range a_uint32s {
		if idx >= len(b_uint32s) {
			return 1
		}
		if c == b_uint32s[idx] {
			continue
		}

		if c < b_uint32s[idx] {
			return -1
		}
		return 1
	}
	if len(a_uint32s) == len(b_uint32s) {
		return 0
	}
	return -1
}

func convertOid(a interface{}) *SnmpOid {
	o, ok := a.(SnmpOid)
	if ok {
		return &o
	}
	v, ok := a.(*OidAndValue)
	if ok {
		return &v.Oid
	}
	panic("a1 is not OidAndValue")
}

func compareOidAdValueWith(a1, b1 Item) int {
	r := compareOidAdValue(a1, b1)
	if r > 0 {
		fmt.Println(convertOid(a1).String() + ">" + convertOid(b1).String())
	} else if r < 0 {
		fmt.Println(convertOid(a1).String() + "<" + convertOid(b1).String())
	} else {
		fmt.Println(convertOid(a1).String() + "==" + convertOid(b1).String())
	}

	return r
}

func NewMibTree() *Tree {
	return NewTree(compareOidAdValue)
}

type UdpServer struct {
	name       string
	origin     string
	conn       net.PacketConn
	listenAddr net.Addr
	waitGroup  sync.WaitGroup
	priv_type  PrivType
	priv_key   []byte

	mibs *Tree
}

func NewUdpServerFromFile(nm, addr, file string) (*UdpServer, error) {
	srv := &UdpServer{name: nm,
		origin: addr,
		mibs:   NewMibTree()}
	r, e := os.Open(nm)
	if nil != e {
		return nil, e
	}
	if e := Read(r, func(oid SnmpOid, value SnmpValue) error {
		if ok := srv.mibs.Insert(&OidAndValue{Oid: oid,
			Value: value}); !ok {
			return errors.New("insert '" + oid.String() + "' failed.")
		}
		return nil
	}); nil != e {
		return nil, e
	}
	return srv, srv.start()
}

func NewUdpServerFromString(nm, addr, mibs string) (*UdpServer, error) {
	srv := &UdpServer{name: nm,
		origin: addr,
		mibs:   NewMibTree()}
	if e := Read(bytes.NewReader([]byte(mibs)), func(oid SnmpOid, value SnmpValue) error {
		if ok := srv.mibs.Insert(&OidAndValue{Oid: oid,
			Value: value}); !ok {
			return errors.New("insert '" + oid.String() + "' failed.")
		}
		return nil
	}); nil != e {
		return nil, e
	}
	return srv, srv.start()
}

func (self *UdpServer) ReloadMibsFromString(mibs string) error {
	self.mibs = NewMibTree()
	if e := Read(bytes.NewReader([]byte(mibs)), func(oid SnmpOid, value SnmpValue) error {
		if ok := self.mibs.Insert(&OidAndValue{Oid: oid,
			Value: value}); !ok {
			return errors.New("insert '" + oid.String() + "' failed.")
		}
		return nil
	}); nil != e {
		return e
	}
	return nil
}
func (self *UdpServer) GetPort() string {
	s := self.listenAddr.String()
	if i := strings.LastIndex(s, ":"); -1 != i {
		return s[i+1:]
	}
	return ""
}

func (self *UdpServer) Close() {
	self.conn.Close()
	self.waitGroup.Wait()
}

func (self *UdpServer) start() error {
	var conn net.PacketConn
	var e error

	if nil == self.listenAddr {
		conn, e = net.ListenPacket("udp", self.origin)
	} else {
		conn, e = net.ListenPacket("udp", self.listenAddr.String())
	}
	if nil != e {
		return e
	}

	self.conn = conn
	self.listenAddr = conn.LocalAddr()

	self.waitGroup.Add(1)
	go self.serve()

	return nil
}

func (self *UdpServer) serve() {
	defer func() {
		self.conn = nil
		self.waitGroup.Done()
	}()

	var cached_bytes [10240]byte

	for {
		recv_bytes, addr, err := self.conn.ReadFrom(cached_bytes[:])
		if nil != err {
			log.Println("[", self.name, "]", err.Error())
			break
		}

		pdu, err := DecodePDU(cached_bytes[:recv_bytes], self.priv_type, self.priv_key, false)
		if nil != err {
			log.Println("[", self.name, "]", err.Error())
			continue
		}

		if pdu.GetVersion() == SNMP_V3 {
			log.Println("[", self.name, "] snmp v3 is not supported.")
			continue
		}

		switch p := pdu.(type) {
		case *V2CPDU:
			self.on_v2(addr, p, cached_bytes[:])
		default:
			log.Println("[", self.name, "] snmp v3 is not supported.")
		}
	}
}

func (self *UdpServer) on_v2(addr net.Addr, p *V2CPDU, cached_bytes []byte) {
	res := &V2CPDU{}
	res.SetVersion(p.GetVersion())
	res.SetType(SNMP_PDU_RESPONSE) //p.GetType(),
	res.SetRequestID(p.GetRequestID())
	res.SetMaxMsgSize(p.GetMaxMsgSize())

	switch p.GetType() {
	case SNMP_PDU_GET:
		for _, vb := range p.GetVariableBindings().All() {
			v := self.GetValueByOid(vb.Oid)
			if nil == v {
				continue
			}
			res.GetVariableBindings().AppendWith(vb.Oid, v)
		}
	case SNMP_PDU_GETNEXT:
		for _, vb := range p.GetVariableBindings().All() {
			o, v := self.GetNextValueByOid(vb.Oid)
			if nil == v {
				continue
			}
			res.GetVariableBindings().AppendWith(o, v)
		}
	default:
		log.Println("[", self.name, "] snmp type is not supported.")
	}

	s, e := EncodePDU(res, cached_bytes, false)
	if nil != e {
		log.Println("[warn]", e)
		return
	}
	if _, e := self.conn.WriteTo(s, addr); nil != e {
		log.Println("[warn]", e)
		return
	}
}

func (self *UdpServer) GetValueByOid(oid SnmpOid) SnmpValue {
	if v := self.mibs.Get(oid); nil != v {
		if sv, ok := v.(*OidAndValue); ok {
			return sv.Value
		}
		panic(fmt.Sprintf("it is not a snmpvalue - [%T]%v", v, v))
	}
	return nil
}

func (self *UdpServer) GetNextValueByOid(oid SnmpOid) (SnmpOid, SnmpValue) {
	it := self.mibs.FindGE(oid)
	if it.Limit() {
		return nil, nil
	}
	v := it.Item()
	if nil == v {
		return nil, nil
	}
	sv, ok := v.(*OidAndValue)
	if !ok {
		panic(fmt.Sprintf("it is not a snmpvalue - [%T]%v", v, v))
	}

	if 0 != compareOidAdValue(oid, sv.Oid) {
		return sv.Oid, sv.Value
	}
	it = it.Next()
	if it.Limit() {
		return nil, nil
	}
	v = it.Item()
	if nil == v {
		return nil, nil
	}
	sv, ok = v.(*OidAndValue)
	if ok {
		return sv.Oid, sv.Value
	}
	panic(fmt.Sprintf("it is not a snmpvalue - [%T]%v", v, v))
}
