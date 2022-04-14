package mmtls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"

	log "github.com/sirupsen/logrus"
)

type dataRecord struct {
	dataType uint32
	seq      uint32
	data     []byte
}

type mmtlsRecord struct {
	recordType uint8
	version    uint16
	length     uint16
	data       []byte
}

func (d *dataRecord) serialize() []byte {
	length := uint32(len(d.data) + 16)
	buf := make([]byte, length)

	binary.BigEndian.PutUint32(buf, length)
	binary.BigEndian.PutUint16(buf[4:], 0x10)
	binary.BigEndian.PutUint16(buf[6:], 0x1)
	binary.BigEndian.PutUint32(buf[8:], d.dataType)
	binary.BigEndian.PutUint32(buf[12:], d.seq)

	if length > 16 {
		copy(buf[16:], d.data)
	}

	return buf
}

func createHandshakeRecord(data []byte) *mmtlsRecord {
	return createRecord(MagicHandshake, data)
}

func createDataRecord(dataType uint32, seq uint32, data []byte) *mmtlsRecord {
	r := &dataRecord{
		dataType: dataType,
		seq:      seq,
		data:     data,
	}
	return createRecord(MagicRecord, r.serialize())
}

func createRecord(recordType uint8, data []byte) *mmtlsRecord {
	return &mmtlsRecord{
		recordType: recordType,
		version:    ProtocolVersion,
		length:     uint16(len(data)),
		data:       data,
	}
}

func readRecord(buf []byte) *mmtlsRecord {
	r := &mmtlsRecord{}

	r.recordType = buf[0]
	r.version = binary.BigEndian.Uint16(buf[1:])
	r.length = binary.BigEndian.Uint16(buf[3:])
	r.data = make([]byte, r.length)
	copy(r.data, buf[5:])

	return r
}

func (r *mmtlsRecord) serialize() []byte {
	buf := make([]byte, r.length+5)

	buf[0] = r.recordType
	binary.BigEndian.PutUint16(buf[1:], r.version)
	binary.BigEndian.PutUint16(buf[3:], r.length)
	copy(buf[5:], r.data)

	return buf
}

func (r *mmtlsRecord) encrypt(keys *trafficKeyPair, clientSeqNum uint32) error {
	c, err := aes.NewCipher(keys.clientKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	copy(nonce, keys.clientNonce)
	xorNonce(nonce, clientSeqNum)

	auddit := make([]byte, 13)
	binary.BigEndian.PutUint64(auddit, uint64(clientSeqNum))
	auddit[8] = r.recordType
	binary.BigEndian.PutUint16(auddit[9:], r.version)
	// GCM add 16-byte tag
	binary.BigEndian.PutUint16(auddit[11:], r.length+16)

	dst := aead.Seal(nil, nonce, r.data, auddit)

	log.Debugf("Encrypt(%d/%d):\n%s\n", len(r.data), len(dst), hex.Dump(dst))

	r.data = dst
	r.length = uint16(len(dst))

	return nil
}

func (r *mmtlsRecord) decrypt(keys *trafficKeyPair, serverSeqNum uint32) error {
	c, err := aes.NewCipher(keys.serverKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	copy(nonce, keys.serverNonce)
	xorNonce(nonce, serverSeqNum)
	auddit := make([]byte, 13)
	binary.BigEndian.PutUint64(auddit, uint64(serverSeqNum))
	auddit[8] = r.recordType
	binary.BigEndian.PutUint16(auddit[9:], r.version)
	binary.BigEndian.PutUint16(auddit[11:], r.length)

	dst, err := aead.Open(nil, nonce, r.data, auddit)
	if err != nil {
		return err
	}

	log.Debugf("Decrypt:\n%s\n", hex.Dump(dst))

	r.data = dst
	r.length = uint16(len(dst))

	return nil
}
