package snmpclient

import (
	"fmt"
	"net"
	"strings"
)

func NormalizeIP(s string) string {
	if "" == s {
		return s
	}
	addr := net.ParseIP(s)
	if nil != addr {
		return addr.String()
	}

	addr = net.ParseIP(strings.Replace(s, "_", ".", -1))
	if nil != addr {
		return addr.String()
	}
	return s
}

func NormalizePort(s string) string {
	//if nil == s || 0 == len(s) {
	return s
	//}
}

func NormalizeAddress(s string) string {
	if "" == s {
		return s
	}

	idx := strings.IndexRune(s, ':')
	if -1 == idx {
		idx = strings.IndexRune(s, ',')
		if -1 == idx {
			return NormalizeIP(s) + ":161"
		}
	}
	return NormalizeIP(s[0:idx]) + ":" + NormalizePort(s[idx+1:])
}

type snmpException struct {
	code    SnmpResult
	message string
}

func (err *snmpException) Error() string {
	return err.message
}

func (err *snmpException) Code() SnmpResult {
	return err.code
}

// Errorf formats according to a format specifier and returns the string 
// as a value that satisfies error.
func Errorf(code SnmpResult, format string, a ...interface{}) SnmpError {
	return &snmpException{code: code, message: fmt.Sprintf(format, a...)}
}

func Error(code SnmpResult, msg string) SnmpError {
	return &snmpException{code: code, message: msg}
}

func newError(code SnmpResult, err error, msg string) SnmpError {
	if "" == msg {
		return &snmpException{code: code, message: err.Error()}
	}
	if nil == err {
		return &snmpException{code: code, message: msg}
	}
	return &snmpException{code: code, message: msg + " - " + err.Error()}
}

type Writer interface {
	IsEnabled() bool

	Printf(format string, v ...interface{})
	Print(v ...interface{})
}

type nullWriter struct {
}

func (l *nullWriter) IsEnabled() bool { return false }

func (l *nullWriter) Printf(format string, v ...interface{}) {}

func (l *nullWriter) Print(v ...interface{}) {}

type fmtWriter struct {
}

func (l *fmtWriter) IsEnabled() bool { return true }

func (l *fmtWriter) Printf(format string, v ...interface{}) {
	fmt.Printf(format, v...)
}

func (l *fmtWriter) Print(v ...interface{}) {
	fmt.Println(v...)
}
