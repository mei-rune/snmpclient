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

func counter64_to_uint64(v *C.snmp_values_t) (uint64, error) {
	return uint64(C.snmp_value_get_uint64(v)), nil
}

func uint64_to_counter64(u64 uint64, v *C.snmp_values_t) {
	C.snmp_value_put_uint64(v, C.uint64_t(u64))
}
