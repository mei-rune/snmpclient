package snmpclient

import (
	"testing"
	"time"
)

func TestRequestBuffer(t *testing.T) {
	cb := newRequestBuffer(make([]*clientRequest, 10))

	check := func(cb *requestBuffer, c int) {
		if c < 10 {
			if cb.Size() != (1 + c) {
				t.Error("size is error, excepted is", 1+c, ", actual is", cb.Size())
			}

			all := cb.All()
			if len(all) != (1 + c) {
				t.Error("len(all) is error, excepted is 10, actual is", cb.Size())
			}

			for i := 0; i <= c; i++ {
				if all[i].timeout != time.Duration(i) {
					t.Error("all[", i, "] is error, excepted is ", all[i].timeout, ", actual is", i)
				}
			}

			for i := 0; i <= c; i++ {
				if all[i].timeout != cb.Get(i).timeout {
					t.Error("all[", i, "] != cb.Get(", i, "), excepted is ", all[i].timeout, ", actual is", cb.Get(i).timeout)
				}
			}

			if time.Duration(c) != cb.Last().timeout {
				t.Error("excepted last is", c, ", actual is", cb.Last().timeout)
			}

			if all[0].timeout != cb.First().timeout {
				t.Error("excepted first is", all[0].timeout, ", actual is", cb.First().timeout)
			}

		} else {
			if cb.Size() != 10 {
				t.Error("size is error, excepted is 10, actual is", cb.Size())
			}

			all := cb.All()
			if len(all) != 10 {
				t.Error("len(all) is error, excepted is 10, actual is", cb.Size())
			}

			for i := 0; i < 10; i++ {
				if all[i].timeout != time.Duration(c-9+i) {
					t.Error("all[", i, "] is error, excepted is", all[i].timeout, ", actual is", c-9+i)
				}
			}

			for i := 0; i < 10; i++ {
				if all[i].timeout != cb.Get(i).timeout {
					t.Error("all[", i, "] != cb.Get(", i, "), excepted is ", all[i].timeout, ", actual is", cb.Get(i).timeout)
				}
			}

			if time.Duration(c) != cb.Last().timeout {
				t.Error("excepted last is", c, ", actual is", cb.Last().timeout)
			}

			if time.Duration(c-9) != cb.First().timeout {
				t.Error("excepted first is", c-9, ", actual is", cb.First().timeout)
			}

			if all[0].timeout != cb.First().timeout {
				t.Error("excepted first is", all[0].timeout, ", actual is", cb.First().timeout)
			}

			if all[len(all)-1].timeout != cb.Last().timeout {
				t.Error("excepted first is", all[len(all)-1].timeout, ", actual is", cb.Last().timeout)
			}
		}
	}

	for i := 0; i < 100; i++ {
		cb.Push(&clientRequest{timeout: time.Duration(i)})
		check(cb, i)
	}
}
