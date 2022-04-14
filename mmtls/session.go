package mmtls

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
