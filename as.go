package snmpclient

import (
	"errors"
)

// func bytesToString(bs []byte, charset string) string {
// 	charset, _ := params["charset"]
// 	decoder := mahonia.NewDecoder(charset)
// 	if nil == decoder {
// 		return string(bs), nil
// 	}

// 	var buffer bytes.Buffer
// 	for 0 != len(bs) {
// 		c, length, status := decoder(bs)
// 		switch status {
// 		case mahonia.SUCCESS:
// 			buffer.WriteRune(c)
// 			bs = bs[length:]
// 		case mahonia.INVALID_CHAR:
// 			buffer.Write([]byte{'.'})
// 			bs = bs[1:]
// 		case mahonia.NO_ROOM:
// 			buffer.Write([]byte{'.'})
// 			bs = bs[0:0]
// 		case mahonia.STATE_ONLY:
// 			bs = bs[length:]
// 		}
// 	}
// 	return buffer.String()
// }

// func AsString(value SnmpValue, charset string) (string, error) {
// 	if SNMP_SYNTAX_OCTETSTRING == value.GetSyntax() {
// 		return bytesToString(params, v.GetBytes())
// 	}
// 	return "", errors.New("value is not string - '" + value.String() + "'.")
// }

func AsInt(value SnmpValue) (int, error) {
	a, err := AsInt32(value)
	return int(a), err
}

func AsUint(value SnmpValue) (uint, error) {
	a, err := AsUint32(value)
	return uint(a), err
}

// Int type AsSerts to `float64` then converts to `int`
func AsInt64(value SnmpValue) (int64, error) {
	switch value.GetSyntax() {
	case SNMP_SYNTAX_INTEGER:
		return value.GetInt64(), nil
	case SNMP_SYNTAX_GAUGE, SNMP_SYNTAX_COUNTER, SNMP_SYNTAX_TIMETICKS:
		return value.GetInt64(), nil
	case SNMP_SYNTAX_COUNTER64:
		if 9223372036854775807 >= value.GetUint64() {
			return int64(value.GetUint64()), nil
		}
	}
	return 0, errors.New("type Assertion to int64 failed")
}

func AsInt32(value SnmpValue) (int32, error) {
	switch value.GetSyntax() {
	case SNMP_SYNTAX_INTEGER:
		return value.GetInt32(), nil
	case SNMP_SYNTAX_GAUGE, SNMP_SYNTAX_COUNTER, SNMP_SYNTAX_TIMETICKS:
		u32 := value.GetUint32()
		if 2147483647 < u32 {
			return 0, errors.New("type Assertion to int32 failed, it is too big.")
		}
		return int32(u32), nil
	case SNMP_SYNTAX_COUNTER64:
		u64 := value.GetUint64()
		if 2147483647 < u64 {
			return 0, errors.New("type Assertion to int32 failed, it is too big.")
		}
		return int32(u64), nil
	}
	return 0, errors.New("type Assertion to int64 failed")
}

// Uint type AsSerts to `float64` then converts to `int`
func AsUint64(value SnmpValue) (uint64, error) {
	switch value.GetSyntax() {
	case SNMP_SYNTAX_INTEGER:
		if 0 <= value.GetInt32() {
			return uint64(value.GetInt32()), nil
		}
	case SNMP_SYNTAX_GAUGE, SNMP_SYNTAX_COUNTER, SNMP_SYNTAX_TIMETICKS:
		return uint64(value.GetUint32()), nil
	case SNMP_SYNTAX_COUNTER64:
		return value.GetUint64(), nil
	}
	return 0, errors.New("type Assertion to int64 failed")
}

func AsUint32(value SnmpValue) (uint32, error) {
	switch value.GetSyntax() {
	case SNMP_SYNTAX_INTEGER:
		if 0 <= value.GetInt32() {
			return uint32(value.GetInt32()), nil
		}
	case SNMP_SYNTAX_GAUGE, SNMP_SYNTAX_COUNTER, SNMP_SYNTAX_TIMETICKS:
		return uint32(value.GetUint32()), nil
	case SNMP_SYNTAX_COUNTER64:
		u64 := value.GetUint64()
		if 4294967295 < u64 {
			return 0, errors.New("type AsUint32 to uint32 failed, it is too big.")
		}
		return uint32(u64), nil
	}
	return 0, errors.New("type Assertion to int64 failed")
}
