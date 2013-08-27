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
	"bytes"
	"encoding/hex"
	"strconv"
	"unsafe"
)

const (
	MAX_COMMUNITY_LEN     = 128
	SNMP_ENGINE_ID_LEN    = 32
	SNMP_CONTEXT_NAME_LEN = 32
	SNMP_AUTH_KEY_LEN     = 40
	SNMP_PRIV_KEY_LEN     = 32
	SNMP_ADM_STR32_LEN    = 32
)

type V2CPDU struct {
	version          SnmpVersion
	op               SnmpType
	requestId        int
	target           string
	community        string
	variableBindings VariableBindings
	maxMsgSize       uint

	max_repetitions int
	non_repeaters   int
}

func (pdu *V2CPDU) Init(params map[string]string) SnmpError {

	pdu.maxMsgSize = *maxPDUSize
	if v, ok := params["snmp.max_msg_size"]; ok {
		if num, e := strconv.ParseUint(v, 10, 0); nil == e {
			pdu.maxMsgSize = uint(num)
		}
	}

	if v, ok := params["snmp.max_repetitions"]; ok {
		if num, e := strconv.ParseInt(v, 10, 0); nil == e {
			pdu.max_repetitions = int(num)
		}
	}

	if v, ok := params["snmp.non_repeaters"]; ok {
		if num, e := strconv.ParseInt(v, 10, 0); nil == e {
			pdu.non_repeaters = int(num)
		}
	}

	community, ok := params["snmp.community"]
	if ok && "" != community {
		pdu.community = community
		return nil
	}
	return Error(SNMP_CODE_FAILED, "community is empty.")
}

func (pdu *V2CPDU) GetRequestID() int {
	return pdu.requestId
}

func (pdu *V2CPDU) SetRequestID(id int) {
	pdu.requestId = id
}

func (pdu *V2CPDU) GetVersion() SnmpVersion {
	return pdu.version
}

func (pdu *V2CPDU) GetType() SnmpType {
	return pdu.op
}

func (pdu *V2CPDU) GetTarget() string {
	return pdu.target
}

func (pdu *V2CPDU) GetVariableBindings() *VariableBindings {
	return &pdu.variableBindings
}

func (pdu *V2CPDU) String() string {
	var buffer bytes.Buffer
	buffer.WriteString(pdu.op.String())
	buffer.WriteString(" variableBindings")
	buffer.WriteString(pdu.variableBindings.String())
	buffer.WriteString(" from ")
	buffer.WriteString(pdu.target)
	buffer.WriteString(" with community = '")
	buffer.WriteString(pdu.community)
	buffer.WriteString("' and requestId='")
	buffer.WriteString(strconv.Itoa(pdu.GetRequestID()))
	buffer.WriteString("' and version='")
	buffer.WriteString(pdu.version.String())
	if SNMP_PDU_GETBULK == pdu.op {
		buffer.WriteString("' and max_repetitions='")
		buffer.WriteString(strconv.Itoa(pdu.max_repetitions))
		buffer.WriteString("' and non_repeaters='")
		buffer.WriteString(strconv.Itoa(pdu.non_repeaters))
	}
	buffer.WriteString("'")
	return buffer.String()
}

func (pdu *V2CPDU) encodePDU(is_dump bool) ([]byte, SnmpError) {
	var internal C.snmp_pdu_t
	C.snmp_pdu_init(&internal)
	defer C.snmp_pdu_free(&internal)

	if SNMP_PDU_GETBULK == pdu.op {
		if pdu.variableBindings.Len() < pdu.non_repeaters {
			internal.error_status = C.int32_t(pdu.variableBindings.Len())
		} else {
			internal.error_status = C.int32_t(pdu.non_repeaters)
		}

		if pdu.max_repetitions > 0 {
			internal.error_index = C.int32_t(pdu.max_repetitions)
		} else {
			internal.error_index = C.int32_t(1)
		}
	}

	err := strcpy(&internal.community[0], MAX_COMMUNITY_LEN, pdu.community)
	if nil != err {
		return nil, newError(SNMP_CODE_FAILED, err, "copy community")
	}

	internal.engine.max_msg_size = C.int32_t(pdu.maxMsgSize)
	internal.request_id = C.int32_t(pdu.requestId)
	internal.pdu_type = C.u_int(pdu.op)
	internal.version = uint32(pdu.version)

	err = encodeBindings(&internal, pdu.GetVariableBindings())

	if nil != err {
		return nil, newError(SNMP_CODE_FAILED, err, "encode bindings")
	}

	if is_test {
		debug_init_secparams(&internal)
	} else {
		C.snmp_pdu_init_secparams(&internal)
	}

	if is_dump {
		C.snmp_pdu_dump(&internal)
	}

	return encodeNativePdu(&internal)
}

func (pdu *V2CPDU) decodePDU(native *C.snmp_pdu_t) (bool, SnmpError) {

	native.community[MAX_COMMUNITY_LEN-1] = 0
	pdu.community = C.GoString(&native.community[0])

	pdu.requestId = int(native.request_id)
	pdu.op = SnmpType(native.pdu_type)
	pdu.version = SnmpVersion(native.version)

	decodeBindings(native, pdu.GetVariableBindings())

	if C.SNMP_ERR_NOERROR != native.error_status {
		ret_code := uint32(C.SNMP_CODE_ERR_NOERROR + native.error_status)
		err := Error(SnmpResult(ret_code), "check pdu failed, "+C.GoString(C.snmp_get_error(ret_code)))
		return true, err //newError(, err, "check pdu failed")
	}

	return true, nil
}

type V3PDU struct {
	op               SnmpType
	requestId        int
	identifier       int
	target           string
	securityModel    securityModelWithCopy
	variableBindings VariableBindings
	maxMsgSize       uint
	contextName      string
	contextEngine    []byte
	engine           *snmpEngine

	max_repetitions int
	non_repeaters   int
}

func (pdu *V3PDU) Init(params map[string]string) (err SnmpError) {
	var e error

	pdu.maxMsgSize = *maxPDUSize

	if v, ok := params["snmp.max_msg_size"]; ok {
		if num, e := strconv.ParseUint(v, 10, 0); nil == e {
			pdu.maxMsgSize = uint(num)
		}
	}

	if v, ok := params["snmp.max_repetitions"]; ok {
		if num, e := strconv.ParseInt(v, 10, 0); nil == e {
			pdu.max_repetitions = int(num)
		}
	}

	if v, ok := params["snmp.non_repeaters"]; ok {
		if num, e := strconv.ParseInt(v, 10, 0); nil == e {
			pdu.non_repeaters = int(num)
		}
	}

	if s, ok := params["snmp.context_name"]; ok {
		pdu.contextName = s
		if s, ok = params["snmp.context_engine"]; ok {
			pdu.contextEngine, e = hex.DecodeString(s)
			if nil != e {
				return newError(SNMP_CODE_FAILED, e, "'context_engine' decode failed")
			}
		}
	}

	pdu.identifier = -1
	if s, ok := params["snmp.identifier"]; ok {
		pdu.identifier, e = strconv.Atoi(s)
		if nil != e {
			return newError(SNMP_CODE_FAILED, e, "'identifier' decode failed")
		}
	}

	if s, ok := params["snmp.engine_id"]; ok {
		pdu.engine = new(snmpEngine)
		pdu.engine.engine_id, e = hex.DecodeString(s)
		if nil != e {
			return newError(SNMP_CODE_FAILED, e, "'engine_id' decode failed")
		}

		if s, ok = params["snmp.engine_boots"]; ok {
			pdu.engine.engine_boots, e = strconv.Atoi(s)
			if nil != e {
				return newError(SNMP_CODE_FAILED, e, "'engine_boots' decode failed")
			}
		}
		if s, ok = params["snmp.engine_time"]; ok {
			pdu.engine.engine_time, e = strconv.Atoi(s)
			if nil != e {
				return newError(SNMP_CODE_FAILED, e, "'engine_time' decode failed")
			}
		}
	}
	pdu.securityModel, err = NewSecurityModel(params)
	return
}

func (pdu *V3PDU) GetRequestID() int {
	return pdu.requestId
}

func (pdu *V3PDU) SetRequestID(id int) {
	pdu.requestId = id
	pdu.identifier = id
}

func (pdu *V3PDU) GetVersion() SnmpVersion {
	return SNMP_V3
}

func (pdu *V3PDU) GetType() SnmpType {
	return pdu.op
}

func (pdu *V3PDU) GetTarget() string {
	return pdu.target
}

func (pdu *V3PDU) GetVariableBindings() *VariableBindings {
	return &pdu.variableBindings
}

func (pdu *V3PDU) String() string {
	var buffer bytes.Buffer
	buffer.WriteString(pdu.op.String())
	buffer.WriteString(" variableBindings")
	buffer.WriteString(pdu.variableBindings.String())
	buffer.WriteString(" from ")
	buffer.WriteString(pdu.target)
	buffer.WriteString(" with ")
	if nil == pdu.securityModel {
		buffer.WriteString("securityModel is nil")
	} else {
		buffer.WriteString(pdu.securityModel.String())
	}
	buffer.WriteString(" and contextName='")
	buffer.WriteString(pdu.contextName)
	buffer.WriteString("' and contextEngine=")

	if nil == pdu.contextEngine {
		buffer.WriteString("nil")
	} else {
		buffer.WriteString("'")
		buffer.WriteString(hex.EncodeToString(pdu.contextEngine))
		buffer.WriteString("'")
	}

	buffer.WriteString(" and ")
	if nil == pdu.securityModel {
		buffer.WriteString("securityModel is nil")
	} else {
		buffer.WriteString(pdu.securityModel.String())
	}
	buffer.WriteString(" and requestId='")
	buffer.WriteString(strconv.Itoa(pdu.GetRequestID()))
	buffer.WriteString(". and identifier='")
	buffer.WriteString(strconv.Itoa(pdu.identifier))
	buffer.WriteString("' and version='v3'")
	if SNMP_PDU_GETBULK == pdu.op {
		buffer.WriteString("' and max_repetitions='")
		buffer.WriteString(strconv.Itoa(pdu.max_repetitions))
		buffer.WriteString("' and non_repeaters='")
		buffer.WriteString(strconv.Itoa(pdu.non_repeaters))
	}
	return buffer.String()
}

func (pdu *V3PDU) encodePDU(is_dump bool) ([]byte, SnmpError) {
	var internal C.snmp_pdu_t
	C.snmp_pdu_init(&internal)
	defer C.snmp_pdu_free(&internal)
	internal.request_id = C.int32_t(pdu.requestId)
	internal.pdu_type = C.u_int(pdu.op)
	internal.version = uint32(SNMP_V3)

	if SNMP_PDU_GETBULK == pdu.op {
		if pdu.variableBindings.Len() < pdu.non_repeaters {
			internal.error_status = C.int32_t(pdu.variableBindings.Len())
		} else {
			internal.error_status = C.int32_t(pdu.non_repeaters)
		}

		if pdu.max_repetitions > 0 {
			internal.error_index = C.int32_t(pdu.max_repetitions)
		} else {
			internal.error_index = C.int32_t(1)
		}
	}

	if pdu.identifier < 0 {
		internal.identifier = C.int32_t(pdu.requestId)
	} else {
		internal.identifier = C.int32_t(pdu.identifier)
	}
	internal.flags = 0

	if nil == pdu.contextEngine {
		internal.context_engine_len = C.uint32_t(0)
	} else {
		err := memcpy(&internal.context_engine[0], SNMP_ENGINE_ID_LEN, pdu.contextEngine)
		if nil != err {
			return nil, newError(SNMP_CODE_FAILED, err, "copy context_engine failed")
		}
		internal.context_engine_len = C.uint32_t(len(pdu.contextEngine))
	}

	err := strcpy(&internal.context_name[0], SNMP_CONTEXT_NAME_LEN, pdu.contextName)
	if nil != err {
		return nil, newError(SNMP_CODE_FAILED, err, "copy context_name failed")
	}

	if nil != pdu.engine {
		err = memcpy(&internal.engine.engine_id[0], SNMP_ENGINE_ID_LEN, pdu.engine.engine_id)
		if nil != err {
			return nil, newError(SNMP_CODE_FAILED, err, "copy engine_id failed")
		}
		internal.engine.engine_len = C.uint32_t(len(pdu.engine.engine_id))
		internal.engine.engine_boots = C.int32_t(pdu.engine.engine_boots)
		internal.engine.engine_time = C.int32_t(pdu.engine.engine_time)
	}

	if 0 == pdu.maxMsgSize {
		pdu.maxMsgSize = *maxPDUSize
	}
	internal.engine.max_msg_size = C.int32_t(pdu.maxMsgSize)

	internal.security_model = SNMP_SECMODEL_USM
	if nil == pdu.securityModel {
		return nil, newError(SNMP_CODE_FAILED, nil, "security model is nil")
	}
	err = pdu.securityModel.Write(&internal.user)

	if nil != err {
		return nil, newError(SNMP_CODE_FAILED, err, "fill security model failed")
	}

	err = encodeBindings(&internal, pdu.GetVariableBindings())

	if nil != err {
		return nil, newError(SNMP_CODE_FAILED, err, "fill encode bindings failed")
	}

	if is_test {
		debug_init_secparams(&internal)
	} else {
		C.snmp_pdu_init_secparams(&internal)
	}

	if is_dump {
		C.snmp_pdu_dump(&internal)
	}
	return encodeNativePdu(&internal)
}

func (pdu *V3PDU) decodePDU(native *C.snmp_pdu_t) (bool, SnmpError) {

	pdu.requestId = int(native.request_id)
	pdu.identifier = int(native.identifier)
	pdu.op = SnmpType(native.pdu_type)

	pdu.contextEngine = readGoBytes(&native.context_engine[0], native.context_engine_len)
	pdu.contextName = readGoString(&native.context_name[0], SNMP_CONTEXT_NAME_LEN)

	pdu.engine = new(snmpEngine)
	pdu.engine.engine_id = readGoBytes(&native.engine.engine_id[0], native.engine.engine_len)
	pdu.engine.engine_boots = int(native.engine.engine_boots)
	pdu.engine.engine_time = int(native.engine.engine_time)
	pdu.maxMsgSize = uint(native.engine.max_msg_size)

	pdu.securityModel = new(USM)
	err := pdu.securityModel.Read(&native.user)

	if nil != err {
		return false, newError(SNMP_CODE_FAILED, err, "read security model failed")
	}

	decodeBindings(native, pdu.GetVariableBindings())

	if native.pdu_type == C.SNMP_PDU_REPORT {
		ret_code := C.snmp_check_bad_oids(native)
		if ret_code != 0 {
			err = Error(SnmpResult(ret_code), "check pdu failed, "+C.GoString(C.snmp_get_error(ret_code)))
			return true, err //newError(, err, "check pdu failed")
		}
	}

	if C.SNMP_ERR_NOERROR != native.error_status {
		ret_code := uint32(C.SNMP_CODE_ERR_NOERROR + native.error_status)
		err = Error(SnmpResult(ret_code), "check pdu failed, "+C.GoString(C.snmp_get_error(ret_code)))
		return true, err //newError(, err, "check pdu failed")
	}

	return true, nil
}

///////////////////////// Encode/Decode /////////////////////////////

const (
	ASN_MAXOIDLEN     = 128
	SNMP_MAX_BINDINGS = 100
)

func oidWrite(dst *C.asn_oid_t, value SnmpValue) SnmpError {
	uintArray := value.GetUint32s()
	if ASN_MAXOIDLEN <= len(uintArray) {
		return Errorf(SNMP_CODE_FAILED, "oid is too long, maximum size is %d, oid is %s", ASN_MAXOIDLEN, value.String())
	}

	for i, subOid := range uintArray {
		dst.subs[i] = C.asn_subid_t(subOid)
	}
	dst.len = C.u_int(len(uintArray))
	return nil
}

func oidRead(src *C.asn_oid_t) *SnmpOid {
	subs := make([]uint32, src.len)
	for i := 0; i < int(src.len); i++ {
		subs[i] = uint32(src.subs[i])
	}
	return NewOid(subs)
}

var is_test bool = false
var debug_salt []byte = make([]byte, 8)

func debug_test_enable() {
	is_test = true
}

func debug_test_disable() {
	is_test = false
}

func debug_init_secparams(pdu *C.snmp_pdu_t) {
	if pdu.user.auth_proto != C.SNMP_AUTH_NOAUTH {
		pdu.flags |= C.SNMP_MSG_AUTH_FLAG
	}

	switch pdu.user.priv_proto {
	case C.SNMP_PRIV_DES:
		memcpy(&pdu.msg_salt[0], 8, debug_salt)
		pdu.flags |= C.SNMP_MSG_PRIV_FLAG
	case C.SNMP_PRIV_AES:
		memcpy(&pdu.msg_salt[0], 8, debug_salt)
		pdu.flags |= C.SNMP_MSG_PRIV_FLAG
	}
}

func encodeNativePdu(pdu *C.snmp_pdu_t) ([]byte, SnmpError) {
	if pdu.engine.max_msg_size == 0 {
		pdu.engine.max_msg_size = C.int32_t(*maxPDUSize)
	}

	bytes := make([]byte, int(pdu.engine.max_msg_size))
	var buffer C.asn_buf_t
	C.set_asn_u_ptr(&buffer.asn_u, (*C.char)(unsafe.Pointer(&bytes[0])))
	buffer.asn_len = C.size_t(len(bytes))

	ret_code := C.snmp_pdu_encode(pdu, &buffer)
	if 0 != ret_code {
		err := Error(SnmpResult(ret_code), C.GoString(C.snmp_pdu_get_error(pdu, ret_code)))
		return nil, err
	}
	length := C.get_buffer_length(&buffer, (*C.u_char)(unsafe.Pointer(&bytes[0])))
	return bytes[0:length], nil
}

func encodeBindings(internal *C.snmp_pdu_t, vbs *VariableBindings) SnmpError {

	if SNMP_MAX_BINDINGS < vbs.Len() {
		return Errorf(SNMP_CODE_FAILED, "bindings too long, SNMP_MAX_BINDINGS is %d, variableBindings is %d",
			SNMP_MAX_BINDINGS, vbs.Len())
	}

	for i, vb := range vbs.All() {
		err := oidWrite(&internal.bindings[i].oid, &vb.Oid)
		if nil != err {
			internal.nbindings = C.u_int(i) + 1 // free
			return err
		}

		if nil == vb.Value {
			internal.bindings[i].syntax = uint32(SNMP_SYNTAX_NULL)
			continue
		}

		internal.bindings[i].syntax = uint32(vb.Value.GetSyntax())
		switch vb.Value.GetSyntax() {
		case SNMP_SYNTAX_NULL:
		case SNMP_SYNTAX_INTEGER:
			C.snmp_value_put_int32(&internal.bindings[i].v, C.int32_t(vb.Value.GetInt32()))
		case SNMP_SYNTAX_OCTETSTRING:
			bytes := vb.Value.GetBytes()
			C.snmp_value_put_octets(&internal.bindings[i].v, unsafe.Pointer(&bytes[0]), C.u_int(len(bytes)))
		case SNMP_SYNTAX_OID:
			err = oidWrite(C.snmp_value_get_oid(&internal.bindings[i].v), vb.Value)
			if nil != err {
				internal.nbindings = C.u_int(i) + 1 // free
				return err
			}
		case SNMP_SYNTAX_IPADDRESS:
			bytes := vb.Value.GetBytes()
			if 4 != len(bytes) {
				internal.nbindings = C.u_int(i) + 1 // free
				return Errorf(SNMP_CODE_FAILED, "ip address is error, it's length is %d, excepted length is 4, value is %s",
					len(bytes), vb.Value.String())
			}
			C.snmp_value_put_ipaddress(&internal.bindings[i].v, C.u_char(bytes[0]),
				C.u_char(bytes[1]), C.u_char(bytes[2]), C.u_char(bytes[3]))
		case SNMP_SYNTAX_COUNTER:
			C.snmp_value_put_uint32(&internal.bindings[i].v, C.uint32_t(vb.Value.GetUint32()))
		case SNMP_SYNTAX_GAUGE:
			C.snmp_value_put_uint32(&internal.bindings[i].v, C.uint32_t(vb.Value.GetUint32()))
		case SNMP_SYNTAX_TIMETICKS:
			C.snmp_value_put_uint32(&internal.bindings[i].v, C.uint32_t(vb.Value.GetUint32()))
		case SNMP_SYNTAX_COUNTER64:
			// s := strconv.FormatUint(vb.Value.GetUint64(), 10)
			// cs := C.CString(s)
			// defer C.free(unsafe.Pointer(cs))
			// C.snmp_value_put_uint64_str(&internal.bindings[i].v, cs)
			C.snmp_value_put_uint64(&internal.bindings[i].v, C.uint64_t(vb.Value.GetUint64()))
		default:
			internal.nbindings = C.u_int(i) + 1 // free
			return Errorf(SNMP_CODE_FAILED, "unsupported type - %v", vb.Value)
		}
	}
	internal.nbindings = C.u_int(vbs.Len())
	return nil
}

func decodeBindings(internal *C.snmp_pdu_t, vbs *VariableBindings) {

	for i := 0; i < int(internal.nbindings); i++ {
		oid := *oidRead(&internal.bindings[i].oid)

		switch SnmpSyntax(internal.bindings[i].syntax) {
		case SNMP_SYNTAX_NULL:
			vbs.AppendWith(oid, NewSnmpNil())
		case SNMP_SYNTAX_INTEGER:
			vbs.AppendWith(oid, NewSnmpInt32(int32(C.snmp_value_get_int32(&internal.bindings[i].v))))
		case SNMP_SYNTAX_OCTETSTRING:
			l := int(C.snmp_value_get_octets_len(&internal.bindings[i].v))
			bytes := make([]byte, l, l+10)
			if 0 != l {
				C.snmp_value_get_octets(&internal.bindings[i].v, unsafe.Pointer(&bytes[0]))
			}
			vbs.AppendWith(oid, NewSnmpOctetString(bytes))
		case SNMP_SYNTAX_OID:
			v := oidRead(C.snmp_value_get_oid(&internal.bindings[i].v))
			vbs.AppendWith(oid, v)
		case SNMP_SYNTAX_IPADDRESS:
			bytes := make([]byte, 4)
			tmp := C.snmp_value_get_ipaddress(&internal.bindings[i].v)
			C.memcpy(unsafe.Pointer(&bytes[0]), unsafe.Pointer(tmp), 4)
			vbs.AppendWith(oid, NewSnmpAddress(bytes))
		case SNMP_SYNTAX_COUNTER:
			vbs.AppendWith(oid, NewSnmpCounter32(uint32(C.snmp_value_get_uint32(&internal.bindings[i].v))))
		case SNMP_SYNTAX_GAUGE:
			vbs.AppendWith(oid, NewSnmpUint32(uint32(C.snmp_value_get_uint32(&internal.bindings[i].v))))
		case SNMP_SYNTAX_TIMETICKS:
			vbs.AppendWith(oid, NewSnmpTimeticks(uint32(C.snmp_value_get_uint32(&internal.bindings[i].v))))
		case SNMP_SYNTAX_COUNTER64:
			// bytes := make([]byte, 100)
			// len := int(C.snmp_value_get_uint64_str(&internal.bindings[i].v, (*C.char)(unsafe.Pointer(&bytes[0])), 100))
			// u64, err := strconv.ParseUint(string(bytes[0:len]), 10, 64)
			// if nil != err {
			//	panic("read uint64 failed, " + err.Error())
			// }
			// vbs.AppendWith(oid, NewSnmpCounter64(u64))
			vbs.AppendWith(oid, NewSnmpCounter64(uint64(C.snmp_value_get_uint64(&internal.bindings[i].v))))
		default:
			vbs.AppendWith(oid, NewSnmpValueError(uint(internal.bindings[i].syntax)))
		}
	}
}

func DecodePDUHeader(buffer *C.asn_buf_t, pdu *C.snmp_pdu_t) SnmpError {
	C.snmp_pdu_init(pdu)

	ret_code := C.snmp_pdu_decode_header(buffer, pdu)
	if 0 != ret_code {
		return Error(SNMP_CODE_FAILED, "decode pdu header failed -"+C.GoString(C.snmp_pdu_get_error(pdu, ret_code)))
	}
	return nil
}

func FillUser(pdu *C.snmp_pdu_t,
	auth_proto AuthType, auth_key []byte,
	priv_proto PrivType, priv_key []byte) SnmpError {

	pdu.user.auth_proto = uint32(auth_proto)
	err := memcpy(&pdu.user.auth_key[0], C.SNMP_AUTH_KEY_SIZ, auth_key)
	if nil != err {
		return newError(SNMP_CODE_FAILED, err, "set auth_key failed")
	}
	pdu.user.auth_len = C.size_t(len(auth_key))

	pdu.user.priv_proto = uint32(priv_proto)
	err = memcpy(&pdu.user.priv_key[0], C.SNMP_PRIV_KEY_SIZ, priv_key)
	if nil != err {
		return newError(SNMP_CODE_FAILED, err, "set priv_key failed")
	}
	pdu.user.priv_len = C.size_t(len(priv_key))

	return nil
}

func DecodePDUBody(buffer *C.asn_buf_t, pdu *C.snmp_pdu_t) SnmpError {
	var recv_len C.int32_t
	var ret_code uint32

	if C.SNMP_V3 == pdu.version {
		if C.SNMP_SECMODEL_USM != pdu.security_model {
			return Errorf(SNMP_CODE_FAILED, "unsupport security model - %d", int(pdu.security_model))
		}

		if ret_code = C.snmp_pdu_decode_secmode(buffer, pdu); C.SNMP_CODE_OK != ret_code {
			return Error(SnmpResult(ret_code), C.GoString(C.snmp_pdu_get_error(pdu, ret_code)))
		}
	}

	if ret_code = C.snmp_pdu_decode_scoped(buffer, pdu, &recv_len); C.SNMP_CODE_OK != ret_code {
		switch ret_code {
		case C.SNMP_CODE_BADENC:
			if C.SNMP_Verr == pdu.version {
				return Errorf(SNMP_CODE_FAILED, "unsupport security model - %d", int(pdu.security_model))
			}
		}

		return Error(SnmpResult(ret_code), C.GoString(C.snmp_pdu_get_error(pdu, ret_code)))
	}
	return nil
}

func DecodePDU(bytes []byte, priv_type PrivType, priv_key []byte, is_dump bool) (PDU, SnmpError) {
	var buffer C.asn_buf_t
	var pdu C.snmp_pdu_t

	C.set_asn_u_ptr(&buffer.asn_u, (*C.char)(unsafe.Pointer(&bytes[0])))
	buffer.asn_len = C.size_t(len(bytes))

	err := DecodePDUHeader(&buffer, &pdu)
	if nil != err {
		return nil, err
	}
	defer C.snmp_pdu_free(&pdu)

	err = FillUser(&pdu, SNMP_AUTH_NOAUTH, nil, priv_type, priv_key)
	if nil != err {
		return nil, err
	}
	err = DecodePDUBody(&buffer, &pdu)
	if nil != err {
		return nil, err
	}

	if is_dump {
		C.snmp_pdu_dump(&pdu)
	}

	var ok bool = false
	if uint32(SNMP_V3) == pdu.version {
		var v3 V3PDU
		ok, err = v3.decodePDU(&pdu)
		if ok {
			return &v3, err
		}
		return nil, err
	}
	var v2 V2CPDU

	ok, err = v2.decodePDU(&pdu)
	if ok {
		return &v2, err
	}
	return nil, err
}

func EncodePDU(pdu PDU, is_dump bool) ([]byte, SnmpError) {
	if pdu.GetVersion() != SNMP_V3 {
		return pdu.(*V2CPDU).encodePDU(is_dump)
	}
	return pdu.(*V3PDU).encodePDU(is_dump)
}
