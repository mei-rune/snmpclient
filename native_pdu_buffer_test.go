package snmpclient

// import (
// 	"fmt"
// 	"testing"
// )

// func TestNativePduBuffer(t *testing.T) {
// 	cb := newNativePduBuffer(make([]*C.snmp_pdu_t, 10))
// 	check := func(cb *bytesBuffer, c int) {
// 		if c < 10 {
// 			if cb.Size() != (1 + c) {
// 				t.Error("size is error, excepted is", 1+c, ", actual is", cb.Size())
// 			}

// 			all := cb.All()
// 			if len(all) != (1 + c) {
// 				t.Error("len(all) is error, excepted is 10, actual is", cb.Size())
// 			}

// 			for i := 0; i <= c; i++ {
// 				if string(all[i]) != fmt.Sprint(i) {
// 					t.Error("all[", i, "] is error, excepted is ", string(all[i]), ", actual is", i)
// 				}
// 			}

// 			for i := 0; i <= c; i++ {
// 				if string(all[i]) != string(cb.Get(i)) {
// 					t.Error("all[", i, "] != cb.Get(", i, "), excepted is ", string(all[i]), ", actual is", string(cb.Get(i)))
// 				}
// 			}

// 			if fmt.Sprint(c) != string(cb.Last()) {
// 				t.Error("excepted last is", c, ", actual is", string(cb.Last()))
// 			}

// 			if string(all[0]) != string(cb.First()) {
// 				t.Error("excepted first is", string(all[0]), ", actual is", string(cb.First()))
// 			}

// 		} else {
// 			if cb.Size() != 10 {
// 				t.Error("size is error, excepted is 10, actual is", cb.Size())
// 			}

// 			all := cb.All()
// 			if len(all) != 10 {
// 				t.Error("len(all) is error, excepted is 10, actual is", cb.Size())
// 			}

// 			for i := 0; i < 10; i++ {
// 				if string(all[i]) != fmt.Sprint(c-9+i) {
// 					t.Error("all[", i, "] is error, excepted is", string(all[i]), ", actual is", c-9+i)
// 				}
// 			}

// 			for i := 0; i < 10; i++ {
// 				if string(all[i]) != string(cb.Get(i)) {
// 					t.Error("all[", i, "] != cb.Get(", i, "), excepted is ", string(all[i]), ", actual is", string(cb.Get(i)))
// 				}
// 			}

// 			if fmt.Sprint(c) != string(cb.Last()) {
// 				t.Error("excepted last is", c, ", actual is", string(cb.Last()))
// 			}

// 			if fmt.Sprint(c-9) != string(cb.First()) {
// 				t.Error("excepted first is", c-9, ", actual is", string(cb.First()))
// 			}

// 			if string(all[0]) != string(cb.First()) {
// 				t.Error("excepted first is", string(all[0]), ", actual is", string(cb.First()))
// 			}

// 			if string(all[len(all)-1]) != string(cb.Last()) {
// 				t.Error("excepted first is", string(all[len(all)-1]), ", actual is", string(cb.Last()))
// 			}
// 		}
// 	}

// 	for i := 0; i < 100; i++ {
// 		cb.Push([]byte(fmt.Sprint(i)))
// 		check(cb, i)
// 	}
// }
