package mmtls

import "encoding/binary"

type clientFinish struct {
	reversed byte
	data     []byte
}

func newClientFinish(data []byte) *clientFinish {
	return &clientFinish{
		reversed: 0x14,
		data:     data,
	}
}

func (c *clientFinish) serialize() []byte {
	buf := make([]byte, len(c.data)+7)

	binary.BigEndian.PutUint32(buf, uint32(len(c.data)+3))

	buf[4] = c.reversed

	binary.BigEndian.PutUint16(buf[5:], uint16(len(c.data)))

	copy(buf[7:], c.data)

	return buf
}
