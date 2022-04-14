package mmtls

import (
	"bytes"
	"encoding/binary"
	"io"
)

type serverFinish struct {
	reversed byte
	data     []byte
}

func ReadServerFinish(buf []byte) (*serverFinish, error) {
	r := bytes.NewReader(buf)

	s := &serverFinish{}

	// package length
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	// static reversed
	s.reversed, _ = r.ReadByte()

	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	s.data = make([]byte, length)
	if _, err := r.Read(s.data); err != nil {
		return nil, err
	}

	return s, nil
}
