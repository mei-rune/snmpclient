package snmpclient

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/textproto"
	"regexp"
	"strings"
	"unicode"
)

var empty_line = errors.New("data is empty.")
var more_line = errors.New("more line")
var re = regexp.MustCompile(`(iso|\d)(.\d+)*\s=\s.*`)

func ParseString(ss []string, is_end bool, vs string) (SnmpValue, []string, error) {
	simple_line := strings.TrimSpace(vs)
	if !strings.HasPrefix(simple_line, "\"") {
		return nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, \"" + simple_line + "\" is not start with \".")
	}
	if 1 < len(simple_line) {
		if strings.HasSuffix(simple_line, "\"") {
			return NewSnmpOctetString([]byte(simple_line[1 : len(simple_line)-1])), ss[1:], nil
		}
	}

	p := -1
	for idx, sss := range ss[1:] {
		if re.MatchString(sss) {
			p = idx
		}
	}

	if -1 == p {
		if is_end {
			simple_line = strings.TrimLeftFunc(vs, unicode.IsSpace)
			if 1 != len(ss) {
				simple_line = simple_line[1:] + "\r\n" + strings.Join(ss[1:], "\r\n")
			}
			if strings.HasSuffix(simple_line, "\"") {
				simple_line = simple_line[:len(simple_line)-1]
			}
			if strings.HasPrefix(simple_line, "\"") {
				simple_line = simple_line[1:]
			}
			return NewSnmpOctetString([]byte(simple_line)), nil, nil
		}
		return nil, ss, more_line
	}
	p += 1

	simple_line = strings.TrimLeftFunc(vs, unicode.IsSpace)
	if 1 != p {
		simple_line = simple_line + "\r\n" + strings.Join(ss[1:p], "\r\n")
	}
	if strings.HasSuffix(simple_line, "\"") {
		simple_line = simple_line[:len(simple_line)-1]
	}

	if strings.HasPrefix(simple_line, "\"") {
		simple_line = simple_line[1:]
	}

	return NewSnmpOctetString([]byte(simple_line)), ss[p:], nil
}

func ReadHex(buf *bytes.Buffer, s string) error {
	for _, h := range strings.Fields(strings.TrimSpace(s)) {
		if 2 != len(h) {
			return errors.New("decode \"" + s + "\" failed, 'len of " + h + "' is not equals 2.")
		}

		b, e := hex.DecodeString(h)
		if nil != e {
			return errors.New("decode \"" + h + "\" \"" + s + "\" failed, " + e.Error())
		}
		buf.Write(b)
	}
	return nil
}

func ParseHexString(ss []string, is_end bool, vs string) (SnmpValue, []string, error) {
	p := -1
	for idx, sss := range ss[1:] {
		if re.MatchString(sss) {
			p = idx
		}
	}

	if -1 == p {
		if is_end {
			var buf bytes.Buffer
			if e := ReadHex(&buf, strings.TrimSpace(vs)); nil != e {
				return nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, " + e.Error())
			}
			for _, s := range ss[1:] {
				if e := ReadHex(&buf, s); nil != e {
					return nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, " + e.Error())
				}
			}
			return NewSnmpOctetString(buf.Bytes()), nil, nil
		}
		return nil, ss, more_line
	}
	p += 1

	var buf bytes.Buffer
	if e := ReadHex(&buf, strings.TrimSpace(vs)); nil != e {
		return nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, " + e.Error())
	}
	for _, s := range ss[1:p] {
		if e := ReadHex(&buf, s); nil != e {
			return nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, " + e.Error())
		}
	}
	return NewSnmpOctetString(buf.Bytes()), ss[p:], nil
}

func ParseLine(ss []string, is_end bool) (SnmpOid, SnmpValue, []string, error) {
	// fmt.Println("=====================================")
	// fmt.Println(strings.Join(ss, "\r\n"))
	// fmt.Println(is_end)
	// fmt.Println("-------------------------------------")

	if nil == ss || 0 == len(ss) {
		return nil, nil, nil, errors.New("data is nil or empty.")
	}
	for 0 != len(ss) {
		if "" != ss[0] &&
			"End of MIB" != ss[0] &&
			'#' != ss[0][0] {
			break
		}

		ss = ss[1:]
	}
	if nil == ss || 0 == len(ss) {
		return nil, nil, nil, empty_line
	}
	sa := strings.SplitN(ss[0], "=", 2)
	if 2 != len(sa) {
		if strings.Contains(ss[0], "MIB search path") ||
			strings.Contains(ss[0], "Cannot find module") {
			return nil, nil, nil, empty_line
		}
		//MIB search path: c:/usr/share/snmp/mibs
		//Cannot find module (abc): At line 0 in (none)
		return nil, nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, first line is not \"x = y\".")
	}
	oid_str := strings.TrimSpace(strings.Replace(sa[0], "iso", "1", 1))
	oid, e := ParseOidFromString(oid_str)
	if nil != e {
		return nil, nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, " + e.Error())
	}

	tv := strings.SplitN(sa[1], ":", 2)
	if 2 != len(tv) {
		// iso.3.6.1.4.1.6339.100.7.1.1.7.1 = ""
		simple_line := strings.TrimSpace(sa[1])
		if 1 == len(ss) {
			if strings.HasPrefix(simple_line, "\"") &&
				strings.HasSuffix(simple_line, "\"") {
				v, e := NewSnmpOctetStringFromString(simple_line[1 : len(simple_line)-1])
				return oid, v, nil, e
			}
		}
		return oid, NewSnmpOctetString([]byte(simple_line)), ss[1:], nil
		//return oid, nil, nil, errors.New("parse `" + strings.Join(ss, "\r\n") + "` failed, first line is not \"x = t: y\".")
	}
	t := strings.TrimSpace(tv[0])
	var v SnmpValue
	//var remain []string

	if "STRING" == t {
		v, rr, e := ParseString(ss, is_end, tv[1])
		return oid, v, rr, e
	} else if "Hex-STRING" == t {
		v, rr, e := ParseHexString(ss, is_end, tv[1])
		return oid, v, rr, e
		//Hex-STRING: 00 22 93 5D EF 00
		// iso.3.6.1.2.1.14.4.1.8.0.0.0.0.1.34.2.28.4.34.2.28.4 = Hex-STRING: 00 01 02 01 22 02 1C 04 22 02 1C 04 80 00 78 7D
		// DE E4 00 3C 00 00 00 03 22 02 1C 04 FF FF FF FF
		// 03 00 00 01 22 02 00 01 22 03 1C 1A 01 00 01 E8
		// 22 03 1C 19 FF FF FF FF 03 00 01 E8
	} else {
		if 1 != len(ss) {
			return SnmpOid{}, nil, nil, errors.New("parse `" +
				strings.Join(ss, "\r\n") + "` failed, it is not muti line.")
		}
		switch t {
		case "OID":
			v, e = NewSnmpOidFromString(strings.TrimSpace(strings.Replace(tv[1], "iso", "1", 1)))
		case "INTEGER":
			v, e = NewSnmpInt32FromString(strings.TrimSpace(tv[1]))
		case "Gauge32":
			v, e = NewSnmpUint32FromString(strings.TrimSpace(tv[1]))
		case "Counter32":
			v, e = NewSnmpCounter32FromString(strings.TrimSpace(tv[1]))
		case "Counter64":
			v, e = NewSnmpCounter64FromString(strings.TrimSpace(tv[1]))
		case "Timeticks":
			//Timeticks: (16465600) 1 day, 21:44:16.00
			p1 := strings.IndexRune(tv[1], '(')
			if -1 == p1 {
				return SnmpOid{}, nil, nil, errors.New("parse `" +
					strings.Join(ss, "\r\n") + "` failed, '" + tv[1] + "' is syntex error.")
			}

			p2 := strings.IndexRune(tv[1], ')')
			if -1 == p2 || p1 > p2 {
				return SnmpOid{}, nil, nil, errors.New("parse `" +
					strings.Join(ss, "\r\n") + "` failed, '" + tv[1] + "' is syntex error.")
			}
			v, e = NewSnmpTimeticksFromString(strings.TrimSpace(tv[1][p1+1 : p2]))
		case "IpAddress":
			v, e = NewSnmpAddressFromString(strings.TrimSpace(tv[1]))
		default:
			return SnmpOid{}, nil, nil, errors.New("parse `" +
				strings.Join(ss, "\r\n") + "` failed, it is not supported.")
		}
	}
	return oid, v, nil, e
}

func Read(reader io.Reader, cb func(oid SnmpOid, value SnmpValue) error) error {
	rd := textproto.NewReader(bufio.NewReader(reader))
	var line string
	var s []string
	var e error
	for {
		line, e = rd.ReadLine()
		if io.EOF == e {
			for nil != s {
				oid, value, remain, e := ParseLine(append(s, line), true)
				if nil != e {
					if empty_line == e {
						s = remain
						continue
					}
					return e
				}

				if e = cb(oid, value); nil != e {
					return e
				}
				if nil == remain || 0 == len(remain) {
					s = nil
				} else {
					s = remain
				}
			}
			break
		}

		if nil != e {
			return e
		}
		s = append(s, line)
	retry:
		oid, value, remain, e := ParseLine(s, false)
		if nil != e {
			if more_line == e {
				continue
			}
			if empty_line == e {
				s = remain
				continue
			}
			return e
		}

		if e = cb(oid, value); nil != e {
			return e
		}

		if nil != remain && len(s) == len(remain) {
			panic("dead parse")
		}
		if nil != remain && 0 != len(remain) {
			s = remain
			goto retry
		}

		s = nil
	}
	return nil
}
