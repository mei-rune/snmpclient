package snmpclient

/* Circular buffer object */
type requestBuffer struct {
	start    int              /* index of oldest element              */
	count    int              /* the count of elements                */
	elements []*clientRequest /* vector of elements                   */
}

func newRequestBuffer(elements []*clientRequest) *requestBuffer {
	return &requestBuffer{elements: elements}
}

func (self *requestBuffer) Init(elements []*clientRequest) {
	self.elements = elements
	self.start = 0
	self.count = 0
}

/* clear all elements.*/
func (self *requestBuffer) Clear() {
	self.start = 0
	self.count = 0
}

func (self *requestBuffer) IsFull() bool {
	return self.count == len(self.elements)
}

/* return true while size is 0, otherwise return false */
func (self *requestBuffer) IsEmpty() bool {
	return 0 == self.count
}

/* Write an element, overwriting oldest element if buffer is full. App can
   choose to avoid the overwrite by checking isFull(). */
func (self *requestBuffer) Push(elem *clientRequest) {
	end := (self.start + self.count) % len(self.elements)
	self.elements[end] = elem
	if self.count == len(self.elements) {
		self.start = (self.start + 1) % len(self.elements) /* full, overwrite */
	} else {
		self.count++
	}
}

func (self *requestBuffer) Get(idx int) *clientRequest {
	if self.IsEmpty() {
		return nil
	}

	current := (self.start + idx) % len(self.elements)
	return self.elements[current]
}

/* Read oldest element. App must ensure !isEmpty() first. */
func (self *requestBuffer) Pop() *clientRequest {
	if self.IsEmpty() {
		return nil
	}

	elem := self.elements[self.start]
	self.start = (self.start + 1) % len(self.elements)
	self.count--
	return elem
}

func (self *requestBuffer) First() *clientRequest {
	if self.IsEmpty() {
		return nil
	}

	return self.elements[self.start]
}

func (self *requestBuffer) Last() *clientRequest {
	if self.IsEmpty() {
		return nil
	}

	end := (self.start + self.count - 1) % len(self.elements)
	return self.elements[end]
}

/* Read all elements.*/
func (self *requestBuffer) Size() int {
	return self.count
}

/* Read all elements.*/
func (self *requestBuffer) All() []*clientRequest {
	if 0 == self.count {
		return nil
	}

	res := make([]*clientRequest, 0, self.count)
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
