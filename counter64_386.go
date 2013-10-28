package snmpclient

// #include "bsnmp/config.h"
// #include <stdlib.h>
// #include "bsnmp/asn1.h"
// #include "bsnmp/snmp.h"
// #include "bsnmp/gobindings.h"
//
// #cgo CFLAGS: -O0 -g3
// #cgo windows LDFLAGS: -lws2_32
import "C"

import (
	"strconv"
	"unsafe"
)

func counter64_to_uint64(v *C.snmp_values_t) (uint64, error) {
	bytes := make([]byte, 100)
	len := int(C.snmp_value_get_uint64_str(v, (*C.char)(unsafe.Pointer(&bytes[0])), 100))
	return strconv.ParseUint(string(bytes[0:len]), 10, 64)
}

func uint64_to_counter64(u64 uint64, v *C.snmp_values_t) {
	s := strconv.FormatUint(u64, 10)
	cs := C.CString(s)
	C.snmp_value_put_uint64_str(v, cs)
	C.free(unsafe.Pointer(cs))
}

//vbs.AppendWith(oid, NewSnmpCounter64(uint64(C.snmp_value_get_uint64(&internal.bindings[i].v))))
