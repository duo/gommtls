package mmtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"io"
)

type serverHello struct {
	protocolVersion uint16
	cipherSuites    uint16
	publicKey       *ecdsa.PublicKey
}

func readServerHello(buf []byte) (*serverHello, error) {
	r := bytes.NewReader(buf)

	hello := &serverHello{}

	var packLen uint32
	if err := binary.Read(r, binary.BigEndian, &packLen); err != nil {
		return nil, err
	}

	if len(buf) != int(packLen)+4 {
		return nil, errors.New("data corrupted")
	}

	// skip flag
	if _, err := r.Seek(1, io.SeekCurrent); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &hello.protocolVersion); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &hello.cipherSuites); err != nil {
		return nil, err
	}

	// skip server random
	if _, err := r.Seek(32, io.SeekCurrent); err != nil {
		return nil, err
	}

	// skip exntensions package length
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	// skip extensions count
	if _, err := r.Seek(1, io.SeekCurrent); err != nil {
		return nil, err
	}

	// skip extension package length
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	// skip extension type
	if _, err := r.Seek(2, io.SeekCurrent); err != nil {
		return nil, err
	}

	// skip extension array index
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	var keyLen uint16
	if err := binary.Read(r, binary.BigEndian, &keyLen); err != nil {
		return nil, err
	}

	ecPoint := make([]byte, keyLen)
	if _, err := r.Read(ecPoint); err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(curve, ecPoint)

	hello.publicKey = &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return hello, nil
}
