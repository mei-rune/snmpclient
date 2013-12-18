package snmpclient

// #include "bsnmp/config.h"
// #include <stdlib.h>
// #include "bsnmp/asn1.h"
// #include "bsnmp/snmp.h"
import "C"

/* Circular buffer object */
type nativePduBuffer struct {
	start    int             /* index of oldest element              */
	count    int             /* the count of elements                */
	elements []*C.snmp_pdu_t /* vector of elements                   */
}

func newNativePduBuffer(elements []*C.snmp_pdu_t) *nativePduBuffer {
	return &nativePduBuffer{elements: elements}
}

func (self *nativePduBuffer) Init(elements []*C.snmp_pdu_t) {
	self.elements = elements
	self.start = 0
	self.count = 0
}

/* clear all elements.*/
func (self *nativePduBuffer) Clear() {
	self.start = 0
	self.count = 0
}

func (self *nativePduBuffer) IsFull() bool {
	return self.count == len(self.elements)
}

/* return true while size is 0, otherwise return false */
func (self *nativePduBuffer) IsEmpty() bool {
	return 0 == self.count
}

/* Write an element, overwriting oldest element if buffer is full. App can
   choose to avoid the overwrite by checking isFull(). */
func (self *nativePduBuffer) Push(elem *C.snmp_pdu_t) {
	end := (self.start + self.count) % len(self.elements)
	self.elements[end] = elem
	if self.count == len(self.elements) {
		self.start = (self.start + 1) % len(self.elements) /* full, overwrite */
	} else {
		self.count++
	}
}

func (self *nativePduBuffer) Get(idx int) *C.snmp_pdu_t {
	if self.IsEmpty() {
		return nil
	}

	current := (self.start + idx) % len(self.elements)
	return self.elements[current]
}

/* Read oldest element. App must ensure !isEmpty() first. */
func (self *nativePduBuffer) Pop() *C.snmp_pdu_t {
	if self.IsEmpty() {
		return nil
	}

	elem := self.elements[self.start]
	self.start = (self.start + 1) % len(self.elements)
	self.count--
	return elem
}

func (self *nativePduBuffer) First() *C.snmp_pdu_t {
	if self.IsEmpty() {
		return nil
	}

	return self.elements[self.start]
}

func (self *nativePduBuffer) Last() *C.snmp_pdu_t {
	if self.IsEmpty() {
		return nil
	}

	end := (self.start + self.count - 1) % len(self.elements)
	return self.elements[end]
}

/* Read all elements.*/
func (self *nativePduBuffer) Size() int {
	return self.count
}

/* Read all elements.*/
func (self *nativePduBuffer) All() []*C.snmp_pdu_t {
	if 0 == self.count {
		return []*C.snmp_pdu_t{}
	}

	res := make([]*C.snmp_pdu_t, 0, self.count)
	if self.count <= (len(self.elements) - self.start) {
		for i := self.start; i < (self.start + self.count); i++ {
			res = append(res, self.elements[i])
		}
		return res
	}

	for i := self.start; i < len(self.elements); i++ {
		res = append(res, self.elements[i])
	}
	for i := 0; len(res) < self.count; i++ {
		res = append(res, self.elements[i])
	}

	return res
}
