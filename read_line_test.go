package snmpclient

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	for idx, test := range []struct {
		line   []string
		oid    string
		value  string
		e      string
		remain []string
		is_end bool
	}{{line: []string{"iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"},
		oid:   "[oid]1.3.6.1.2.1.1.2.0",
		value: "[oid]1.3.6.1.4.1.6339.1.1.3.4"},
		{line: []string{"iso.3.6.1.2.1.1.3.0 = Timeticks: (16465600) 1 day, 21:44:16.00"},
			oid:   "[oid]1.3.6.1.2.1.1.3.0",
			value: "[timeticks]16465600"},
		{line: []string{"iso.3.6.1.2.1.2.1.0 = INTEGER: 66"},
			oid:   "[oid]1.3.6.1.2.1.2.1.0",
			value: "[int32]66"},
		{line: []string{"iso.3.6.1.2.1.2.2.1.5.88 = Gauge32: 1000000000"},
			oid:   "[oid]1.3.6.1.2.1.2.2.1.5.88",
			value: "[gauge]1000000000"},
		{line: []string{"iso.3.6.1.2.1.2.2.1.10.2 = Counter32: 1940587667"},
			oid:   "[oid]1.3.6.1.2.1.2.2.1.10.2",
			value: "[counter32]1940587667"},
		{line: []string{"iso.3.6.1.2.1.2.2.1.10.2 = Counter64: 19405876345535617"},
			oid:   "[oid]1.3.6.1.2.1.2.2.1.10.2",
			value: "[counter64]19405876345535617"},
		{line: []string{"iso.3.6.1.2.1.2.2.1.10.2 = IpAddress: 12.12.12.0"},
			oid:   "[oid]1.3.6.1.2.1.2.2.1.10.2",
			value: "[ip]12.12.12.0"},

		{line: []string{"iso.3.6.1.2.1.1.4.0 = STRING: \"800-810-9119\""},
			oid:   "[oid]1.3.6.1.2.1.1.4.0",
			value: "[octets]" + hex.EncodeToString([]byte("800-810-9119"))},
		{line: []string{"iso.3.6.1.2.1.1.4.0 = STRING: \"800-810-9119"},
			oid:    "[oid]1.3.6.1.2.1.1.4.0",
			value:  "",
			remain: []string{"iso.3.6.1.2.1.1.4.0 = STRING: \"800-810-9119"},
			e:      more_line.Error()},
		{line: []string{"iso.3.6.1.2.1.1.4.0 = STRING: \"800-810-9119", "800-810-9119\""},
			oid:    "[oid]1.3.6.1.2.1.1.4.0",
			value:  "[octets]" + hex.EncodeToString([]byte("800-810-9119\r\n800-810-9119")),
			is_end: true},
		{line: []string{"iso.3.6.1.2.1.1.4.0 = STRING: \"800-810-9119", "800-810-9119"},
			oid:    "[oid]1.3.6.1.2.1.1.4.0",
			value:  "[octets]" + hex.EncodeToString([]byte("800-810-9119\r\n800-810-9119")),
			is_end: true},
		{line: []string{"iso.3.6.1.2.1.1.4.0 = STRING: \"800-810-9119\"", "iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"},
			oid:    "[oid]1.3.6.1.2.1.1.4.0",
			value:  "[octets]" + hex.EncodeToString([]byte("800-810-9119")),
			remain: []string{"iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"}},
		{line: []string{"iso.3.6.1.2.1.1.4.0 = STRING: \"800-810-9119", "800-810-9119\"", "iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"},
			oid:    "[oid]1.3.6.1.2.1.1.4.0",
			value:  "[octets]" + hex.EncodeToString([]byte("800-810-9119\r\n800-810-9119")),
			remain: []string{"iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"}},
		{line: []string{"iso.3.6.1.2.1.1.4.0 = STRING: \"800-810-9119", "800-810", "-9119\"", "iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"},
			oid:    "[oid]1.3.6.1.2.1.1.4.0",
			value:  "[octets]" + hex.EncodeToString([]byte("800-810-9119\r\n800-810\r\n-9119")),
			remain: []string{"iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"}},
		{line: []string{"iso.3.6.1.2.1.1.4.0 = \"\""},
			oid:   "[oid]1.3.6.1.2.1.1.4.0",
			value: "[octets]" + hex.EncodeToString([]byte(""))},

		// iso.3.6.1.2.1.14.4.1.8.0.0.0.0.1.34.2.28.4.34.2.28.4 = Hex-STRING: 00 01 02 01 22 02 1C 04 22 02 1C 04 80 00 78 7D
		{line: []string{"iso.3.6.1.2.1.1.4.0 = Hex-STRING: 00 01 02 01 22 02 1C 04 22 02 1C 04 80 00 78 7D"},
			oid:    "[oid]1.3.6.1.2.1.1.4.0",
			value:  "[octets]0001020122021c0422021c048000787d",
			is_end: true},

		{line: []string{"iso.3.6.1.2.1.1.4.0 = Hex-STRING: 00 01 02 01 22 02 1C", "04 22 02 1C 04 80 00 78 7D"},
			oid:    "[oid]1.3.6.1.2.1.1.4.0",
			value:  "[octets]0001020122021c0422021c048000787d",
			is_end: true},

		{line: []string{"iso.3.6.1.2.1.1.4.0 = Hex-STRING: 00 01 02 01 22 02 1C 04 22 02 1C 04 80 00 78 7D",
			"iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"},
			oid:    "[oid]1.3.6.1.2.1.1.4.0",
			value:  "[octets]0001020122021c0422021c048000787d",
			remain: []string{"iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"}},

		{line: []string{"iso.3.6.1.2.1.1.4.0 = Hex-STRING: 00 01 02 01 22 02 1C", "04 22 02 1C 04", "80 00 78 7D",
			"iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"},
			oid:    "[oid]1.3.6.1.2.1.1.4.0",
			value:  "[octets]0001020122021c0422021c048000787d",
			remain: []string{"iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4"}},
	} {
		oid, v, r, e := ReadLine(test.line, test.is_end)
		if oid.String() != test.oid {
			t.Errorf("test[%d] failed, oid[%v!=%v] ", idx, oid.String(), test.oid)
		}

		if ("" != test.value && nil == v) ||
			("" == test.value && nil != v) ||
			("" != test.value && v.String() != test.value) {
			if nil != v {
				t.Errorf("test[%d] failed, value[%v!=%v] ", idx, v.String(), test.value)
			} else {
				t.Errorf("test[%d] failed, value[%v!=%v] ", idx, v, test.value)
			}
		}
		if ("" != test.e && nil == e) ||
			("" == test.e && nil != e) ||
			("" != test.e && !strings.Contains(e.Error(), test.e)) {
			t.Errorf("test[%d] failed, error[%v!=%v] ", idx, e, test.e)
		}

		if (isEmpty(test.remain) && !isEmpty(r)) ||
			(!isEmpty(test.remain) && isEmpty(r)) ||
			(!isEmpty(test.remain) && !isEmpty(r) && !reflect.DeepEqual(test.remain, r)) {
			t.Errorf("test[%d] failed, remain[%v!=%v] ", idx, r, test.remain)
		}
	}

	count := 0
	if e := Read(bytes.NewReader([]byte(`iso.3.6.1.2.1.10.166.8.1.3.1.8.267 = Hex-STRING: 04 41 0D 01 
iso.3.6.1.2.1.10.166.8.1.3.1.8.268 = STRING: "
(d/"
iso.3.6.1.2.1.10.166.8.1.3.1.8.269 = Hex-STRING: 0A 14 64 0F`)), func(oid SnmpOid, value SnmpValue) error {
		count++
		if 1 == count {
			if "1.3.6.1.2.1.10.166.8.1.3.1.8.267" != oid.GetString() ||
				"[octets]04410d01" != value.String() {
				t.Error(oid.String(), value)
			}
		} else if 2 == count {
			if "1.3.6.1.2.1.10.166.8.1.3.1.8.268" != oid.GetString() ||
				"[octets]0d0a28642f" != value.String() {
				t.Error(oid.String(), value)
			}
		}
		return nil
	}); nil != e {
		t.Error(e)
	}

}

func isEmpty(a []string) bool {
	return nil == a || 0 == len(a)
}

var mib_string = `iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.6339.1.1.3.4
iso.3.6.1.2.1.1.3.0 = Timeticks: (16465600) 1 day, 21:44:16.00
iso.3.6.1.2.1.2.1.0 = INTEGER: 66
iso.3.6.1.2.1.2.2.1.5.88 = Gauge32: 1000000000
iso.3.6.1.2.1.2.2.1.10.2 = Counter32: 1940587667
iso.3.6.1.2.1.2.2.1.10.3 = Counter64: 19405876345535617
iso.3.6.1.2.1.2.2.1.10.4 = IpAddress: 12.12.12.0
iso.3.6.1.2.1.4.0 = STRING: "800-810-9119"
iso.3.6.1.2.1.6.0 = STRING: "800-810-9119
800-810-9119"
iso.3.6.1.2.1.6.4.0 = STRING: "800-810-9119
800-810
-9119"
iso.3.6.1.2.1.7.4.0 = ""
iso.3.6.1.2.1.8.4.0 = Hex-STRING: 00 01 02 01 22 02 1C 04 22 02 1C 04 80 00 78 7D
iso.3.6.1.2.1.9.4.0 = Hex-STRING: 00 01 02 01 22 02 1C
04 22 02 1C 04
80 00 78 7D
iso.3.6.1.2.1.10.4.0 = Hex-STRING: 00 01 02 01 22 02 1C
04 22 02 1C 04
80 00 78 7D`

var oid_and_value = []struct {
	oid   string
	value string
}{{oid: "[oid]1.3.6.1.2.1.1.2.0",
	value: "[oid]1.3.6.1.4.1.6339.1.1.3.4"},
	{oid: "[oid]1.3.6.1.2.1.1.3.0",
		value: "[timeticks]16465600"},
	{oid: "[oid]1.3.6.1.2.1.2.1.0",
		value: "[int32]66"},
	{oid: "[oid]1.3.6.1.2.1.2.2.1.5.88",
		value: "[gauge]1000000000"},
	{oid: "[oid]1.3.6.1.2.1.2.2.1.10.2",
		value: "[counter32]1940587667"},
	{oid: "[oid]1.3.6.1.2.1.2.2.1.10.3",
		value: "[counter64]19405876345535617"},
	{oid: "[oid]1.3.6.1.2.1.2.2.1.10.4",
		value: "[ip]12.12.12.0"},

	{oid: "[oid]1.3.6.1.2.1.4.0",
		value: "[octets]" + hex.EncodeToString([]byte("800-810-9119"))},
	{oid: "[oid]1.3.6.1.2.1.6.0",
		value: "[octets]" + hex.EncodeToString([]byte("800-810-9119\r\n800-810-9119"))},
	{oid: "[oid]1.3.6.1.2.1.6.4.0",
		value: "[octets]" + hex.EncodeToString([]byte("800-810-9119\r\n800-810\r\n-9119"))},
	{oid: "[oid]1.3.6.1.2.1.7.4.0",
		value: "[octets]" + hex.EncodeToString([]byte(""))},

	// iso.3.6.1.2.1.14.4.1.8.0.0.0.0.1.34.2.28.4.34.2.28.4 = Hex-STRING: 00 01 02 01 22 02 1C 04 22 02 1C 04 80 00 78 7D
	{oid: "[oid]1.3.6.1.2.1.8.4.0",
		value: "[octets]0001020122021c0422021c048000787d"},
	{oid: "[oid]1.3.6.1.2.1.9.4.0",
		value: "[octets]0001020122021c0422021c048000787d"},
	{oid: "[oid]1.3.6.1.2.1.10.4.0",
		value: "[octets]0001020122021c0422021c048000787d"},
}

var next_oid_and_value = []struct {
	oid   string
	value string
}{{oid: "[oid]1.3.6.1.2.1.1.1.0",
	value: "[oid]1.3.6.1.4.1.6339.1.1.3.4"},
	{oid: "[oid]1.3.6",
		value: "[oid]1.3.6.1.4.1.6339.1.1.3.4"},
	{oid: "[oid]1.3.6.1.2.1.1.2.0",
		value: "[timeticks]16465600"},
	{oid: "[oid]1.3.6.1.2.1.1.3.0",
		value: "[int32]66"},
	{oid: "[oid]1.3.6.1.2.1.2.1.0",
		value: "[gauge]1000000000"},
	{oid: "[oid]1.3.6.1.2.1.2.2.1.5.88",
		value: "[counter32]1940587667"},
	{oid: "[oid]1.3.6.1.2.1.2.2.1.10.2",
		value: "[counter64]19405876345535617"},
	{oid: "[oid]1.3.6.1.2.1.2.2.1.10.3",
		value: "[ip]12.12.12.0"},

	{oid: "[oid]1.3.6.1.2.1.2.2.1.10.4",
		value: "[octets]" + hex.EncodeToString([]byte("800-810-9119"))},
	{oid: "[oid]1.3.6.1.2.1.4.0",
		value: "[octets]" + hex.EncodeToString([]byte("800-810-9119\r\n800-810-9119"))},
	{oid: "[oid]1.3.6.1.2.1.6.0",
		value: "[octets]" + hex.EncodeToString([]byte("800-810-9119\r\n800-810\r\n-9119"))},
	{oid: "[oid]1.3.6.1.2.1.6.4.0",
		value: "[octets]" + hex.EncodeToString([]byte(""))},

	// iso.3.6.1.2.1.14.4.1.8.0.0.0.0.1.34.2.28.4.34.2.28.4 = Hex-STRING: 00 01 02 01 22 02 1C 04 22 02 1C 04 80 00 78 7D
	{oid: "[oid]1.3.6.1.2.1.7.4.0",
		value: "[octets]0001020122021c0422021c048000787d"},
	{oid: "[oid]1.3.6.1.2.1.8.4.0",
		value: "[octets]0001020122021c0422021c048000787d"},
	{oid: "[oid]1.3.6.1.2.1.9.4.0",
		value: "[octets]0001020122021c0422021c048000787d"},
}

func TestReadFromString(t *testing.T) {
	srv, e := NewUdpServerFromString("a", ":", mib_string)
	if nil != e {
		t.Error(e)
		return
	}
	defer srv.Close()

	for idx, test := range oid_and_value {
		oid, e := ParseOidFromString(strings.TrimPrefix(test.oid, "[oid]"))
		if nil != e {
			t.Error(e)
			continue
		}
		v := srv.GetValueByOid(oid)
		if nil == v {
			t.Error("test[", idx, "]", test.oid, "is not found.")
			continue
		}

		if v.String() != test.value {
			t.Error("test[", idx, "]", v.String(), "of", test.oid, "is not equals", test.value)
		}
	}

	for idx, test := range next_oid_and_value {
		oid, e := ParseOidFromString(strings.TrimPrefix(test.oid, "[oid]"))
		if nil != e {
			t.Error(e)
			continue
		}
		_, v := srv.GetNextValueByOid(oid)
		if nil == v {
			t.Error("test[", idx, "]", test.oid, "is not found.")
			continue
		}

		if v.String() != test.value {
			t.Error("test[", idx, "]", v.String(), "of", test.oid, "is not equals", test.value)
		}
	}
}

func ReadSnmpValue(addr, oid string, action SnmpType) (SnmpValue, error) {
	cl, e := NewSnmpClient(addr)
	if nil != e {
		return nil, errors.New("create snmp client failed - " + e.Error())
	}
	defer cl.Close()
	req, e := cl.CreatePDU(action, SNMP_V2C)
	if nil != e {
		return nil, errors.New("create pdu failed - " + e.Error())
	}
	req.Init(map[string]string{"snmp.community": "public"})
	err := req.GetVariableBindings().Append(oid, "")
	if nil != err {
		return nil, errors.New("append pdu failed - " + err.Error())
	}
	res, e := cl.SendAndRecv(req, 2*time.Second)
	if nil != e {
		return nil, errors.New("sendAndRecv pdu failed - " + e.Error())
	}
	for i := 0; i < res.GetVariableBindings().Len(); i++ {
		vb := res.GetVariableBindings().Get(i)
		if vb.Oid.GetString() == oid {
			return vb.Value, nil
		}
	}
	if action == SNMP_PDU_GETNEXT {
		return res.GetVariableBindings().Get(0).Value, nil
	}
	return nil, errors.New("not found")
}

func TestSnmpServer(t *testing.T) {
	srv, e := NewUdpServerFromString("a", ":", mib_string)
	if nil != e {
		t.Error(e)
		return
	}
	defer srv.Close()

	for idx, test := range oid_and_value {
		oid := strings.TrimPrefix(test.oid, "[oid]")
		v, e := ReadSnmpValue("127.0.0.1:"+srv.GetPort(), oid, SNMP_PDU_GET)
		if nil != e {
			t.Error("test[", idx, "]", test.oid, e)
			continue
		}

		if v.String() != test.value {
			t.Error("test[", idx, "]", v.String(), "of", test.oid, "is not equals", test.value)
		}
	}

	for idx, test := range next_oid_and_value {
		oid := strings.TrimPrefix(test.oid, "[oid]")
		v, e := ReadSnmpValue("127.0.0.1:"+srv.GetPort(), oid, SNMP_PDU_GETNEXT)
		if nil != e {
			t.Error("testNext[", idx, "]", test.oid, e)
			continue
		}

		if v.String() != test.value {
			t.Error("testNext[", idx, "]", v.String(), "of", test.oid, "is not equals", test.value)
		}
	}
}
