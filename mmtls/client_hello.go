package mmtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/binary"
	"time"
)

type clientHello struct {
	protocolVersion uint16
	cipherSuites    []uint16
	random          []byte
	timestamp       uint32
	extensions      [][]byte
}

// 1-RTT ECDHE
func newECDHEHello(cliPubKey *ecdsa.PublicKey, cliVerKey *ecdsa.PublicKey) *clientHello {
	ch := &clientHello{}

	ch.protocolVersion = ProtocolVersion
	ch.timestamp = uint32(time.Now().Unix())
	ch.random = getRandom(32)
	ch.cipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	ch.extensions = [][]byte{
		elliptic.Marshal(cliPubKey.Curve, cliPubKey.X, cliPubKey.Y),
		elliptic.Marshal(cliVerKey.Curve, cliVerKey.X, cliVerKey.Y),
	}

	return ch
}

// 1-RTT PSK
func NewPskHello(cliPubKey *ecdsa.PublicKey, cliVerKey *ecdsa.PublicKey, ticket *sessionTicket) *clientHello {
	ch := &clientHello{}

	ch.protocolVersion = ProtocolVersion
	ch.timestamp = uint32(time.Now().Unix())
	ch.random = getRandom(32)
	ch.cipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_PSK_WITH_AES_128_GCM_SHA256,
	}

	t := ticket
	t.ticketAgeAdd = make([]byte, 0)
	ticketData, _ := t.serialize()

	ch.extensions = [][]byte{
		ticketData,
		elliptic.Marshal(cliPubKey.Curve, cliPubKey.X, cliPubKey.Y),
		elliptic.Marshal(cliVerKey.Curve, cliVerKey.X, cliVerKey.Y),
	}

	return ch
}

func (c *clientHello) serialize() []byte {
	buf := make([]byte, 0, 512)

	// total length
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// flag ?
	buf = append(buf, 0x01)

	// protocol version
	buf = append(buf, 0x00, 0x00)
	binary.LittleEndian.PutUint16(buf[len(buf)-2:], c.protocolVersion)

	// cipher suites
	buf = append(buf, byte(len(c.cipherSuites)))
	for _, v := range c.cipherSuites {
		buf = append(buf, 0x00, 0x00)
		binary.BigEndian.PutUint16(buf[len(buf)-2:], v)
	}

	// random
	buf = append(buf, c.random...)

	// timestamp
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	binary.BigEndian.PutUint32(buf[len(buf)-4:], uint32(c.timestamp))

	cipherPos := len(buf)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, byte(len(c.cipherSuites)))

	if len(c.cipherSuites) > 1 { // PSK
		pskPos := len(buf)
		buf = append(buf, 0x00, 0x00, 0x00, 0x00)
		buf = append(buf, 0x00, 0x0F) // cipher type?
		buf = append(buf, 0x01)

		keyPos := len(buf)
		buf = append(buf, 0x00, 0x00, 0x00, 0x00)

		buf = append(buf, c.extensions[0]...)
		binary.BigEndian.PutUint32(buf[keyPos:], uint32(len(buf)-keyPos-4))

		binary.BigEndian.PutUint32(buf[pskPos:], uint32(len(buf)-pskPos-4))

		c.extensions = c.extensions[1:]
	}

	// ECDSA keys
	ecdsaPos := len(buf)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	buf = append(buf, 0x00, 0x10) // cipher type?
	buf = append(buf, byte(len(c.extensions)))

	var keyFlag uint32 = 5
	for _, v := range c.extensions {
		keyPos := len(buf)
		buf = append(buf, 0x00, 0x00, 0x00, 0x00)

		buf = append(buf, 0x00, 0x00, 0x00, 0x00)
		binary.BigEndian.PutUint32(buf[len(buf)-4:], keyFlag)
		keyFlag += 1

		buf = append(buf, 0x00, 0x00)
		binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(len(v)))

		buf = append(buf, v...)

		binary.BigEndian.PutUint32(buf[keyPos:], uint32(len(buf)-keyPos-4))
	}

	// magic...
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04)

	// ecdsa length
	binary.BigEndian.PutUint32(buf[ecdsaPos:], uint32(len(buf)-ecdsaPos-4))

	// cipher length
	binary.BigEndian.PutUint32(buf[cipherPos:], uint32(len(buf)-cipherPos-4))

	// struct length
	binary.BigEndian.PutUint32(buf[0:], uint32(len(buf)-4))

	return buf
}
