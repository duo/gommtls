package mmtls

import "io/ioutil"

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
	earlyKey   *trafficKeyPair
}

func (s *Session) Save(path string) error {
	ticketBytes, err := s.tk.serialize()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, ticketBytes, 0644)
}

func LoadSession(path string) (*Session, error) {
	ticketBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ticket, err := readNewSessionTicket(ticketBytes)
	if err != nil {
		return nil, err
	}

	return &Session{
		tk: ticket,
	}, nil
}
