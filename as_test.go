package snmpclient

// import (
// 	"testing"
// )

// func testAsInt32(t *testing.T, v SnmpValue, excepted int32) {

// 	i8, err := AsInt32(v)
// 	if nil != err {
// 		t.Errorf("%v to int32 failed, excepted is %d", v, excepted)
// 	}

// 	if excepted != i8 {
// 		t.Errorf("%v to int32 failed, excepted is %d, actual is %d", v, excepted, i8)
// 	}
// }

// func testAsInt32Failed(t *testing.T, v SnmpValue) {
// 	_, err := AsInt32(v)
// 	if nil == err {
// 		t.Errorf("%v to int32 failed, excepted throw a error, actual return ok", v)
// 	}
// }

// func testAsInt64(t *testing.T, v SnmpValue, excepted int64) {

// 	i8, err := AsInt64(v)
// 	if nil != err {
// 		t.Errorf("%v to int64 failed, excepted is %d", v, excepted)
// 	}

// 	if excepted != i8 {
// 		t.Errorf("%v to int64 failed, excepted is %d, actual is %d", v, excepted, i8)
// 	}
// }

// func testAsInt64Failed(t *testing.T, v SnmpValue) {
// 	_, err := AsInt64(v)
// 	if nil == err {
// 		t.Errorf("%v to int64 failed, excepted throw a error, actual return ok", v)
// 	}
// }

// func testAsUint32(t *testing.T, v SnmpValue, excepted uint32) {

// 	i8, err := AsUint32(v)
// 	if nil != err {
// 		t.Errorf("%v to uint32 failed, excepted is %d", v, excepted)
// 	}

// 	if excepted != i8 {
// 		t.Errorf("%v to uint32 failed, excepted is %d, actual is %d", v, excepted, i8)
// 	}
// }

// func testAsUint32Failed(t *testing.T, v SnmpValue) {
// 	_, err := AsUint32(v)
// 	if nil == err {
// 		t.Errorf("%v to uint32 failed, excepted throw a error, actual return ok", v)
// 	}
// }

// func testAsUint64(t *testing.T, v SnmpValue, excepted uint64) {

// 	i8, err := AsUint64(v)
// 	if nil != err {
// 		t.Errorf("%v to uint64 failed, excepted is %d", v, excepted)
// 	}

// 	if excepted != i8 {
// 		t.Errorf("%v to uint64 failed, excepted is %d, actual is %d", v, excepted, i8)
// 	}
// }

// func testAsUint64Failed(t *testing.T, v SnmpValue) {
// 	_, err := AsUint64(v)
// 	if nil == err {
// 		t.Errorf("%v to uint64 failed, excepted throw a error, actual return ok", v)
// 	}
// }

// func TestAs(t *testing.T) {

// 	testAsInt32(t, SnmpInt32(12), 12)
// 	testAsInt32(t, SnmpCounter32(12), 12)
// 	testAsInt32(t, SnmpUint32(12), 12)
// 	testAsInt32(t, SnmpCounter64(12), 12)

// 	testAsInt32Failed(t, SnmpCounter64(2147483648))

// 	testAsUint32(t, SnmpInt32(12), 12)
// 	testAsUint32(t, SnmpCounter32(12), 12)
// 	testAsUint32(t, SnmpUint32(12), 12)
// 	testAsUint32(t, SnmpCounter64(12), 12)

// 	testAsUint32Failed(t, SnmpCounter64(4294967296))
// 	testAsUint32Failed(t, SnmpInt32(-12))

// 	testAsUint32(t, SnmpInt32(12), 12)
// 	testAsUint32(t, SnmpCounter32(12), 12)
// 	testAsUint32(t, SnmpUint32(12), 12)
// 	testAsUint32(t, SnmpCounter64(12), 12)

// 	testAsUint32Failed(t, SnmpCounter64(18446744073709551616))
// 	testAsUint32Failed(t, SnmpInt32(-12))

// }
