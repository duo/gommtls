package mmtls

import (
	"bytes"
	"encoding/binary"
)

type sessionTicket struct {
	ticketType     byte // reversed unknown
	ticketLifeTime uint32
	ticketAgeAdd   []byte
	reversed       uint32 // always 0x48
	nonce          []byte // 12 bytes nonce
	ticket         []byte
}

type newSessionTicket struct {
	reversed byte
	count    byte
	tickets  []sessionTicket
}

func readNewSessionTicket(buf []byte) (*newSessionTicket, error) {
	r := bytes.NewReader(buf)

	t := &newSessionTicket{}

	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	t.reversed, _ = r.ReadByte()
	t.count, _ = r.ReadByte()

	for i := byte(0); i < t.count; i++ {
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return nil, err
		}
		data := make([]byte, length)
		if _, err := r.Read(data); err != nil {
			return nil, err
		}

		ticket, err := readSessionTicket(data)
		if err != nil {
			return nil, err
		}
		t.tickets = append(t.tickets, *ticket)
	}

	return t, nil
}

func readSessionTicket(buf []byte) (*sessionTicket, error) {
	r := bytes.NewReader(buf)

	t := &sessionTicket{}

	t.ticketType, _ = r.ReadByte()

	if err := binary.Read(r, binary.BigEndian, &t.ticketLifeTime); err != nil {
		return nil, err
	}

	var err error
	t.ticketAgeAdd, err = readU16LenData(r)
	if err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &t.reversed); err != nil {
		return nil, err
	}

	t.nonce, err = readU16LenData(r)
	if err != nil {
		return nil, err
	}

	t.ticket, err = readU16LenData(r)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func (t *sessionTicket) serialize() ([]byte, error) {
	buf := &bytes.Buffer{}

	if err := buf.WriteByte(t.ticketType); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, t.ticketLifeTime); err != nil {
		return nil, err
	}

	if err := writeU16LenData(buf, t.ticketAgeAdd); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, t.reversed); err != nil {
		return nil, err
	}

	if err := writeU16LenData(buf, t.nonce); err != nil {
		return nil, err
	}

	if err := writeU16LenData(buf, t.ticket); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (t *newSessionTicket) serialize() ([]byte, error) {
	buf := &bytes.Buffer{}

	if _, err := buf.Write([]byte{0x00, 0x00, 0x00, 0x00}); err != nil {
		return nil, err
	}
	if err := buf.WriteByte(0x04); err != nil {
		return nil, err
	}
	if err := buf.WriteByte(byte(len(t.tickets))); err != nil {
		return nil, err
	}

	for _, v := range t.tickets {
		vBytes, err := v.serialize()
		if err != nil {
			return nil, err
		}
		writeU32LenData(buf, vBytes)
	}

	data := buf.Bytes()
	binary.BigEndian.PutUint32(data, uint32(len(data)-4))
	return data, nil
}

func (t *newSessionTicket) export() ([]byte, error) {
	earlyDataBuf := &bytes.Buffer{}

	data, err := t.tickets[0].serialize()
	if err != nil {
		return nil, err
	}
	if err := writeU32LenData(earlyDataBuf, data); err != nil {
		return nil, err
	}

	return earlyDataBuf.Bytes(), nil
}
