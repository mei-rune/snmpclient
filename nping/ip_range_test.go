package main

import (
	"reflect"
	"testing"
)

var ip_test = []struct {
	expr   string
	ipList []string
	err    string
	expr2  string
}{{"192.168.1.1", []string{"192.168.1.1"}, "", "192.168.1.1-192.168.1.1"},
	{"192.168.1.1-192.168.1.1", []string{"192.168.1.1"}, "", ""},
	{"192.168.1.1-192.168.1.2", []string{"192.168.1.1", "192.168.1.2"}, "", ""},
	{"192.168.1.1-192.168.1.3", []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}, "", ""},
	{"192.168.1.1/30", []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"}, "", "192.168.1.0-192.168.1.4"},
	{"192.168.1.5-192.168.1.3", nil, "start address geater than end address - '192.168.1.5-192.168.1.3'", ""},
	{"192.168.1.a-192.168.1.3", nil, "start address is syntex error - '192.168.1.a-192.168.1.3'", ""},
	{"192.168.1.5-192.168.1.a", nil, "end address is syntex error - '192.168.1.5-192.168.1.a'", ""},
	{"192.168.15", nil, "syntex error: please input corrent sytex, such 'xxx.xxx.xxx.xxx-yyy.yyy.yyy.yyy - '192.168.15'", ""}}

func TestIPRanage(t *testing.T) {
	for _, raw := range ip_test {
		r, e := ParseIPRange(raw.expr)
		if nil != e {
			if raw.err != e.Error() {
				t.Error(e)
			}
			continue
		}
		ipList := make([]string, 0, 10)
		for r.HasNext() {
			ipList = append(ipList, r.Current().String())
		}

		if !reflect.DeepEqual(ipList, raw.ipList) {
			t.Error(ipList)
			t.Error(raw.ipList)
		}

		if raw.expr2 == "" {
			if raw.expr != r.String() {
				t.Errorf("expr != r.String(), %s, %s", raw.expr, r.String())
			}
		} else if raw.expr2 != r.String() {
			t.Errorf("expr != r.String(), %s, %s", raw.expr2, r.String())
		}
	}

	ips, e := ParseIPRange("192.168.1.1/24")
	if nil != e {
		t.Error("192.168.1.1/24 - " + e.Error())
	} else if "192.168.1.0-192.168.2.0" != ips.String() {
		t.Error(ips.String())
	}
	//for ips.HasNext() {
	//	t.Error(ips.Current().String())
	//}
}
