package mmtls

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

func getRandom(n int) []byte {
	key := make([]byte, n)
	rand.Read(key)
	return key
}

func xorNonce(nonce []byte, seq uint32) {
	seqBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBytes, seq)

	for i := 0; i < 4; i++ {
		pos := len(nonce) - i - 1
		nonce[pos] = nonce[pos] ^ seqBytes[i]
	}
}

func readU16LenData(r io.Reader) ([]byte, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	if length > 0 {
		b := make([]byte, length)
		if _, err := r.Read(b); err != nil {
			return nil, err
		}
		return b, nil
	}
	return nil, nil
}

func writeU32LenData(w io.Writer, d []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(d))); err != nil {
		return err
	}
	if len(d) > 0 {
		if _, err := w.Write(d); err != nil {
			return err
		}
	}
	return nil
}

func writeU16LenData(w io.Writer, d []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(d))); err != nil {
		return err
	}
	if len(d) > 0 {
		if _, err := w.Write(d); err != nil {
			return err
		}
	}
	return nil
}
