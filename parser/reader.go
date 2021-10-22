package parser

import (
	"bufio"
	"io"
	"sync"
)

var readerPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewReader(nil)
	},
}

func getReader(r io.Reader) *bufio.Reader {
	buf := readerPool.Get().(*bufio.Reader)
	buf.Reset(r)
	return buf
}

func putReader(r *bufio.Reader) {
	readerPool.Put(r)
}
