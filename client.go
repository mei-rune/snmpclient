package snmpclient

import (
	"bytes"
	"time"
)

type SnmpVersion int

const (
	SNMP_Verr SnmpVersion = 0
	SNMP_V1   SnmpVersion = 1
	SNMP_V2C  SnmpVersion = 2
	SNMP_V3   SnmpVersion = 3
)

//func (t SnmpVersion) String() string {
//	return t.String()
//}
func (t *SnmpVersion) String() string {
	switch *t {
	case SNMP_V1:
		return "v1"
	case SNMP_V2C:
		return "v2c"
	case SNMP_V3:
		return "v3"
	}
	return "unknown_pdu_version"
}

type AuthType int

const (
	SNMP_AUTH_NOAUTH   AuthType = 0
	SNMP_AUTH_HMAC_MD5 AuthType = 1
	SNMP_AUTH_HMAC_SHA AuthType = 2
)

//func (t *AuthType) String() string {
//	return t.String()
//}

func (t *AuthType) String() string {
	switch *t {
	case SNMP_AUTH_NOAUTH:
		return "noauth"
	case SNMP_AUTH_HMAC_MD5:
		return "md5"
	case SNMP_AUTH_HMAC_SHA:
		return "sha"
	}
	return "unknown_auth_type"
}

type PrivType int

const (
	SNMP_PRIV_NOPRIV PrivType = 0
	SNMP_PRIV_DES    PrivType = 1
	SNMP_PRIV_AES    PrivType = 2
)

func (t *PrivType) String() string {
	switch *t {
	case SNMP_PRIV_NOPRIV:
		return "nopriv"
	case SNMP_PRIV_DES:
		return "des"
	case SNMP_PRIV_AES:
		return "aes"
	}
	return "unknown_priv_type"
}

type SnmpType int

const (
	SNMP_PDU_GET      SnmpType = 0
	SNMP_PDU_GETNEXT  SnmpType = 1
	SNMP_PDU_RESPONSE SnmpType = 2
	SNMP_PDU_SET      SnmpType = 3
	SNMP_PDU_TRAP     SnmpType = 4 /* v1 */
	SNMP_PDU_GETBULK  SnmpType = 5 /* v2 */
	SNMP_PDU_INFORM   SnmpType = 6 /* v2 */
	SNMP_PDU_TRAP2    SnmpType = 7 /* v2 */
	SNMP_PDU_REPORT   SnmpType = 8 /* v2 */

	SNMP_PDU_TABLE SnmpType = 999999
)

func (t *SnmpType) String() string {
	switch *t {
	case SNMP_PDU_GET:
		return "get"
	case SNMP_PDU_GETNEXT:
		return "next"
	case SNMP_PDU_RESPONSE:
		return "response"
	case SNMP_PDU_SET:
		return "set"
	case SNMP_PDU_TRAP:
		return "trap"
	case SNMP_PDU_GETBULK:
		return "getbulk"
	case SNMP_PDU_INFORM:
		return "inform"
	case SNMP_PDU_TRAP2:
		return "trap2"
	case SNMP_PDU_REPORT:
		return "report"
	}
	return "unknown_pdu_type"
}

const (
	SNMP_TRAP_COLDSTART              = 0
	SNMP_TRAP_WARMSTART              = 1
	SNMP_TRAP_LINKDOWN               = 2
	SNMP_TRAP_LINKUP                 = 3
	SNMP_TRAP_AUTHENTICATION_FAILURE = 4
	SNMP_TRAP_EGP_NEIGHBOR_LOSS      = 5
	SNMP_TRAP_ENTERPRISE             = 6

	SNMP_SECMODEL_ANY     = 0
	SNMP_SECMODEL_SNMPv1  = 1
	SNMP_SECMODEL_SNMPv2c = 2
	SNMP_SECMODEL_USM     = 3
	SNMP_SECMODEL_UNKNOWN = 4
)

type SnmpResult int

const (
	SNMP_CODE_OK               SnmpResult = 0
	SNMP_CODE_FAILED           SnmpResult = 1
	SNMP_CODE_BADVERS          SnmpResult = 2
	SNMP_CODE_BADLEN           SnmpResult = 3
	SNMP_CODE_BADENC           SnmpResult = 4
	SNMP_CODE_OORANGE          SnmpResult = 5
	SNMP_CODE_BADSECLEVEL      SnmpResult = 6
	SNMP_CODE_NOTINTIME        SnmpResult = 7
	SNMP_CODE_BADUSER          SnmpResult = 8
	SNMP_CODE_BADENGINE        SnmpResult = 9
	SNMP_CODE_BADDIGEST        SnmpResult = 10
	SNMP_CODE_EDECRYPT         SnmpResult = 11
	SNMP_CODE_BADBINDINGNUMBER SnmpResult = 12
	SNMP_CODE_BADRESULT        SnmpResult = 13
	SNMP_CODE_BADOID           SnmpResult = 14

	SNMP_CODE_SYNTAX_MISMATCH       SnmpResult = 15
	SNMP_CODE_SYNTAX_NOSUCHOBJECT   SnmpResult = 16 /* exception */
	SNMP_CODE_SYNTAX_NOSUCHINSTANCE SnmpResult = 17 /* exception */
	SNMP_CODE_SYNTAX_ENDOFMIBVIEW   SnmpResult = 18 /* exception */

	SNMP_CODE_ERR_TOOBIG         SnmpResult = 19
	SNMP_CODE_ERR_NOSUCHNAME     SnmpResult = 20
	SNMP_CODE_ERR_BADVALUE       SnmpResult = 21
	SNMP_CODE_ERR_READONLY       SnmpResult = 22
	SNMP_CODE_ERR_GENERR         SnmpResult = 23
	SNMP_CODE_ERR_NO_ACCESS      SnmpResult = 24
	SNMP_CODE_ERR_WRONG_TYPE     SnmpResult = 25
	SNMP_CODE_ERR_WRONG_LENGTH   SnmpResult = 26
	SNMP_CODE_ERR_WRONG_ENCODING SnmpResult = 27
	SNMP_CODE_ERR_WRONG_VALUE    SnmpResult = 28
	SNMP_CODE_ERR_NO_CREATION    SnmpResult = 29
	SNMP_CODE_ERR_INCONS_VALUE   SnmpResult = 30
	SNMP_CODE_ERR_RES_UNAVAIL    SnmpResult = 31
	SNMP_CODE_ERR_COMMIT_FAILED  SnmpResult = 32
	SNMP_CODE_ERR_UNDO_FAILED    SnmpResult = 33
	SNMP_CODE_ERR_AUTH_ERR       SnmpResult = 34
	SNMP_CODE_ERR_NOT_WRITEABLE  SnmpResult = 35
	SNMP_CODE_ERR_INCONS_NAME    SnmpResult = 36

	SNMP_CODE_ERR_GOFUNCTION SnmpResult = 37
	SNMP_CODE_BADNET         SnmpResult = 38
	SNMP_CODE_TIMEOUT        SnmpResult = 39
)

type SnmpError interface {
	Error() string
	Code() SnmpResult
}

var (
	ERROR_NOSUCHOBJECT   error = Error(SNMP_CODE_SYNTAX_NOSUCHOBJECT, "nosuchobject")
	ERROR_NOSUCHINSTANCE error = Error(SNMP_CODE_SYNTAX_NOSUCHINSTANCE, "nosuchinstance")
	ERROR_ENDOFMIBVIEW   error = Error(SNMP_CODE_SYNTAX_ENDOFMIBVIEW, "endofmibview")
)

func ToError(v SnmpValue) error {
	switch v.GetSyntax() {
	case SNMP_SYNTAX_NOSUCHOBJECT:
		return ERROR_NOSUCHOBJECT
	case SNMP_SYNTAX_NOSUCHINSTANCE:
		return ERROR_NOSUCHINSTANCE
	case SNMP_SYNTAX_ENDOFMIBVIEW:
		return ERROR_ENDOFMIBVIEW
	default:
		return Error(SNMP_CODE_SYNTAX_MISMATCH, "unknow_snmp_sytax -- "+v.String())
	}
}

///////////////////////// VariableBindings ///////////////////////////////////
type VariableBinding struct {
	Oid   SnmpOid
	Value SnmpValue
}

type VariableBindings struct {
	values []VariableBinding
}

func (vbs *VariableBindings) All() []VariableBinding {
	return vbs.values
}

func (vbs *VariableBindings) Len() int {
	return len(vbs.values)
}

func (vbs *VariableBindings) Get(idx int) VariableBinding {
	return vbs.values[idx]
}

func (vbs *VariableBindings) Put(idx int, oid, value string) error {
	o, ok := ParseOidFromString(oid)
	if nil != ok {
		return ok
	}

	v, ok := NewSnmpValue(value)
	if nil != ok {
		return ok
	}

	vbs.values[idx].Oid = o
	vbs.values[idx].Value = v
	return nil
}

func (vbs *VariableBindings) Append(oid, value string) error {
	o, ok := ParseOidFromString(oid)
	if nil != ok {
		return ok
	}

	var v SnmpValue = NewSnmpNil()
	if "" != value {
		v, ok = NewSnmpValue(value)
		if nil != ok {
			return ok
		}
	}

	return vbs.AppendWith(o, v)
}

func (vbs *VariableBindings) AppendWith(oid SnmpOid, value SnmpValue) error {
	if nil == vbs.values {
		vbs.values = make([]VariableBinding, 0, 20)
	}
	vbs.values = append(vbs.values, VariableBinding{Oid: oid, Value: value})
	return nil
}

func (vbs *VariableBindings) String() string {
	var buffer bytes.Buffer
	buffer.WriteString("[")
	if nil != vbs.values {
		for _, vb := range vbs.values {
			buffer.WriteString(vb.Oid.GetString())
			if nil == vb.Value {
				buffer.WriteString("=nil,")
			} else {
				buffer.WriteString("='")
				buffer.WriteString(vb.Value.GetString())
				buffer.WriteString("',")
			}
		}
	}
	buffer.Truncate(buffer.Len() - 1)
	buffer.WriteString("]")
	return buffer.String()
}

type PDU interface {
	Init(params map[string]string) SnmpError
	SetRequestID(id int)
	GetRequestID() int
	GetVersion() SnmpVersion
	GetType() SnmpType
	//GetTarget() string
	GetVariableBindings() *VariableBindings
	String() string
}

type SecurityModel interface {
	String() string
	IsLocalize() bool
	Localize(key []byte) SnmpError
}

type snmpEngine struct {
	engine_id    []byte
	engine_boots int
	engine_time  int
	max_msg_size uint
}

func (engine *snmpEngine) CopyFrom(src *snmpEngine) {
	//engine.engine_id = make([]byte, len(src.engine_id))
	//copy(engine.engine_id, src.engine_id)
	engine.engine_id = src.engine_id
	engine.engine_boots = src.engine_boots
	engine.engine_time = src.engine_time
	engine.max_msg_size = src.max_msg_size
}

type Client interface {
	CreatePDU(op SnmpType, version SnmpVersion) (PDU, SnmpError)
	SendAndRecv(req PDU, timeout time.Duration) (PDU, SnmpError)
	Stats() interface{}
}
