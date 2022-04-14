package mmtls

import (
	"bytes"
	"encoding/binary"
	"io"
)

type signature struct {
	Type           byte
	EcdsaSignature []byte
}

func readSignature(buf []byte) (*signature, error) {
	r := bytes.NewReader(buf)

	s := &signature{}

	// skip package length
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	// static 0x0f
	s.Type, _ = r.ReadByte()

	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	s.EcdsaSignature = make([]byte, length)
	if _, err := r.Read(s.EcdsaSignature); err != nil {
		return nil, err
	}

	return s, nil
}
