package kuic

import (
	"log"
	"testing"
)

func TestSeq(t *testing.T) {

	seq := newSeqStack()
	log.Println(seq.pop())
	log.Println(seq.pop())
	log.Println(seq.pop())
}
