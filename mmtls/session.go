package mmtls

import (
	"bytes"
	"io/ioutil"
)

type trafficKeyPair struct {
	clientKey   []byte
	serverKey   []byte
	clientNonce []byte
	serverNonce []byte
}

type Session struct {
	tk         *newSessionTicket
	pskAccess  []byte
	pskRefresh []byte
	appKey     *trafficKeyPair
}

func (s *Session) Save(path string) error {
	buf := &bytes.Buffer{}

	if err := writeU16LenData(buf, s.pskAccess); err != nil {
		return err
	}
	if err := writeU16LenData(buf, s.pskRefresh); err != nil {
		return err
	}

	ticketBytes, err := s.tk.serialize()
	if err != nil {
		return err
	}
	buf.Write(ticketBytes)

	return ioutil.WriteFile(path, buf.Bytes(), 0644)
}

func LoadSession(path string) (*Session, error) {
	sessionBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(sessionBytes)
	pskAccess, err := readU16LenData(r)
	if err != nil {
		return nil, err
	}

	pskRefresh, err := readU16LenData(r)
	if err != nil {
		return nil, err
	}

	ticketBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	ticket, err := readNewSessionTicket(ticketBytes)
	if err != nil {
		return nil, err
	}

	return &Session{
		pskAccess:  pskAccess,
		pskRefresh: pskRefresh,
		tk:         ticket,
	}, nil
}
