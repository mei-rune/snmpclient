package snmpclient

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
)

type SVTC struct {
	raw, to, errorMsg string
	isNil             bool
}

func TestSnmp(t *testing.T) {
	tests := []SVTC{SVTC{raw: "[null]", isNil: true},
		SVTC{raw: "[int32]12345"},
		SVTC{raw: "[gauge]2345"},
		SVTC{raw: "[counter32]4521"},
		SVTC{raw: "[counter64]342244343333333332"},
		SVTC{raw: "[octets]" + hex.EncodeToString([]byte("abcdefg"))},
		SVTC{raw: "[oid]2.3.4.5.6"},
		SVTC{raw: "[oid].2.3.4.5.6", to: "[oid]2.3.4.5.6"},
		SVTC{raw: "[oid]_2_3_4_5_6", to: "[oid]2.3.4.5.6"},
		SVTC{raw: "[ip]1.2.3.4"},
		SVTC{raw: "[timeticks]343332"}}

	for _, s := range tests {
		v, e := NewSnmpValue(s.raw)
		toString := s.to
		if "" == toString {
			toString = s.raw
		}
		switch {
		case nil != e:
			t.Errorf("test %s failed. error is %s\r\n", s.raw, e.Error())
		case nil == v:
			t.Errorf("test %s failed. value is nil\r\n", s.raw)
		case s.isNil != v.IsNil():
			t.Errorf("test %s failed. error is isNil()\r\n", s.raw)
		case toString != v.String():
			t.Errorf("test %s failed. error is toString(), result is %s\r\n", s.raw, v.String())
		}
	}

	_, e := NewSnmpValue("124")
	if nil == e || !strings.Contains(e.Error(), "snmp value format error, ") {
		t.Errorf("syntex check error %v", e)
	}
	_, e = NewSnmpValue("[124")
	if nil == e || !strings.Contains(e.Error(), "snmp value format error, ") {
		t.Errorf("syntex check error %v", e)
	}
	_, e = NewSnmpValue("[124]23")
	if nil == e || !strings.Contains(e.Error(), "unsupported snmp type") {
		t.Errorf("syntex check error")
	}

	ip, e := NewSnmpValue("[ip]1.2.3.4")
	if nil != e {
		t.Errorf("ip parse faile. %s", e.Error())
	}

	if 4 != len(ip.GetBytes()) {
		ipaddr := net.IP(ip.GetBytes())
		t.Errorf("ip parse faile. length is not equals 4, len is %d - %s,  %v ", len(ip.GetBytes()), ipaddr.String(), ip.GetBytes())
	}

	tests = []SVTC{SVTC{raw: "[int32]12a345"},
		SVTC{raw: "[gauge]23a45"},
		SVTC{raw: "[counter32]45a21"},
		SVTC{raw: "[counter64]3422a44343333333332"},
		SVTC{raw: "[oid]2..3.4.5.6"},
		SVTC{raw: "[oid].2.3.4.5.a"},
		SVTC{raw: "[ip]1.a.3.4"},
		SVTC{raw: "[timeticks]32a3332"}}

	for _, sv := range tests {
		nv, e := NewSnmpValue(sv.raw)
		substr := sv.errorMsg
		if "" == substr {
			substr = "style error, value is"
		}

		if nil == e {
			t.Errorf("test %s failed. error is e==nil\r\n", sv.raw)
		} else if !strings.Contains(e.Error(), substr) {
			t.Errorf("test %s failed. error is %s\r\n", sv.raw, e.Error())
		}
		if nil != nv {
			fmt.Printf("nv = %v\r\n", nv)
			t.Errorf("test %s failed. error is v!=nil, v is %s\r\n", sv.raw, nv.String())
		}
	}
}
