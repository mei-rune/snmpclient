package snmpclient

/* Circular buffer object */
type bytesBuffer struct {
	start    int      /* index of oldest element              */
	count    int      /* the count of elements                */
	elements [][]byte /* vector of elements                   */
}

func newBytesBuffer(elements [][]byte) *bytesBuffer {
	return &bytesBuffer{elements: elements}
}

func (self *bytesBuffer) Init(elements [][]byte) {
	self.elements = elements
	self.start = 0
	self.count = 0
}

/* clear all elements.*/
func (self *bytesBuffer) Clear() {
	self.start = 0
	self.count = 0
}

func (self *bytesBuffer) IsFull() bool {
	return self.count == len(self.elements)
}

/* return true while size is 0, otherwise return false */
func (self *bytesBuffer) IsEmpty() bool {
	return 0 == self.count
}

/* Write an element, overwriting oldest element if buffer is full. App can
   choose to avoid the overwrite by checking isFull(). */
func (self *bytesBuffer) Push(elem []byte) {
	end := (self.start + self.count) % len(self.elements)
	self.elements[end] = elem
	if self.count == len(self.elements) {
		self.start = (self.start + 1) % len(self.elements) /* full, overwrite */
	} else {
		self.count++
	}
}

func (self *bytesBuffer) Get(idx int) []byte {
	if self.IsEmpty() {
		return nil
	}

	current := (self.start + idx) % len(self.elements)
	return self.elements[current]
}

/* Read oldest element. App must ensure !isEmpty() first. */
func (self *bytesBuffer) Pop() []byte {
	if self.IsEmpty() {
		return nil
	}

	elem := self.elements[self.start]
	self.start = (self.start + 1) % len(self.elements)
	self.count--
	return elem
}

func (self *bytesBuffer) First() []byte {
	if self.IsEmpty() {
		return nil
	}

	return self.elements[self.start]
}

func (self *bytesBuffer) Last() []byte {
	if self.IsEmpty() {
		return nil
	}

	end := (self.start + self.count - 1) % len(self.elements)
	return self.elements[end]
}

/* Read all elements.*/
func (self *bytesBuffer) Size() int {
	return self.count
}

/* Read all elements.*/
func (self *bytesBuffer) All() [][]byte {
	if 0 == self.count {
		return [][]byte{}
	}

	res := make([][]byte, 0, self.count)
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
