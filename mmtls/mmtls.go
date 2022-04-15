package mmtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math/big"
	"net"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
)

var (
	curve = elliptic.P256()
)

type MMTLSClient struct {
	conn net.Conn

	status int32

	publicEcdh *ecdsa.PrivateKey
	verifyEcdh *ecdsa.PrivateKey
	serverEcdh *ecdsa.PublicKey

	handshakeHasher hash.Hash

	serverSeqNum uint32
	clientSeqNum uint32

	Session *Session
}

func NewMMTLSClient() *MMTLSClient {
	c := &MMTLSClient{}

	c.handshakeHasher = sha256.New()

	return c
}

func (c *MMTLSClient) Handshake(host string) error {
	if c.conn == nil {
		conn, err := net.Dial("tcp", host)
		if err != nil {
			return err
		}

		c.conn = conn
	}

	if c.handshakeComplete() {
		return nil
	}

	c.reset()

	if err := c.genKeyPairs(); err != nil {
		return err
	}

	var ch *clientHello
	if c.Session != nil {
		log.Info("1-RTT PSK handshake")
		ch = NewPskHello(&c.publicEcdh.PublicKey, &c.verifyEcdh.PublicKey, &c.Session.tk.tickets[1])
	} else {
		log.Info("1-RTT ECDHE handshake")
		ch = newECDHEHello(&c.publicEcdh.PublicKey, &c.verifyEcdh.PublicKey)
	}
	if err := c.sendClientHello(ch); err != nil {
		return err
	}

	serverHello, err := c.readServerHello()
	if err != nil {
		return err
	}

	// DH compute key
	comKey := c.computeEphemeralSecret(
		serverHello.publicKey.X,
		serverHello.publicKey.Y,
		c.publicEcdh.D)

	// trafffic key
	trafficKey, err := c.computeTrafficKey(
		comKey,
		c.hkdfExpand("handshake key expansion", c.handshakeHasher))
	if err != nil {
		return nil
	}

	// compare traffic key is valid
	if err := c.readSignature(trafficKey); err != nil {
		return err
	}

	// gen psk
	if err := c.readNewSessionTicket(comKey, trafficKey); err != nil {
		return err
	}

	if err := c.readServerFinish(comKey, trafficKey); err != nil {
		return err
	}

	if err := c.sendClientFinish(comKey, trafficKey); err != nil {
		return err
	}

	// ComputeMasterSecre
	expandedSecret := make([]byte, 32)
	hkdf.Expand(
		sha256.New,
		comKey,
		c.hkdfExpand("expanded secret", c.handshakeHasher)).Read(expandedSecret)

	// AppKey
	appKey, _ := c.computeTrafficKey(
		expandedSecret,
		c.hkdfExpand("application data key expansion", c.handshakeHasher))
	c.Session.appKey = appKey

	// Store and reuse
	earlyKey, _ := c.earlyDataKey(c.Session.pskAccess, c.Session.tk)
	c.Session.earlyKey = earlyKey

	// fully complete handshake
	atomic.StoreInt32(&c.status, 1)

	return nil
}

func (c *MMTLSClient) Noop() error {
	if err := c.sendNoop(); err != nil {
		return err
	}

	if err := c.readNoop(); err != nil {
		return err
	}

	return nil
}

func (c *MMTLSClient) Close() error {
	if c.conn != nil {
		log.Debug("Close connection...")
		return c.conn.Close()
	}
	return nil
}

func (c *MMTLSClient) reset() {
	c.handshakeHasher.Reset()

	c.clientSeqNum = 0
	c.serverSeqNum = 0
}

func (c *MMTLSClient) handshakeComplete() bool {
	return atomic.LoadInt32(&c.status) == 1
}

func (c *MMTLSClient) sendClientHello(hello *clientHello) error {
	data := hello.serialize()

	c.handshakeHasher.Write(data)

	packet := createHandshakeRecord(data).serialize()
	log.Debugf("Send ClientHello packet(%d):\n%s", len(packet), hex.Dump(packet))

	_, err := c.conn.Write(packet)

	c.clientSeqNum++

	return err
}

func (c *MMTLSClient) readServerHello() (*serverHello, error) {
	record, err := c.readRecord()
	if err != nil {
		return nil, err
	}

	c.handshakeHasher.Write(record.data)
	c.serverSeqNum++

	return readServerHello(record.data)
}

func (c *MMTLSClient) readSignature(trafficKey *trafficKeyPair) error {
	record, err := c.readRecord()
	if err != nil {
		return err
	}

	if err := record.decrypt(trafficKey, c.serverSeqNum); err != nil {
		return err
	}

	signature, err := readSignature(record.data)
	if err != nil {
		return err
	}

	if !c.verifyEcdsa(signature.EcdsaSignature) {
		return errors.New("verify signature failed")
	}

	c.handshakeHasher.Write(record.data)
	c.serverSeqNum++

	return nil
}

func (c *MMTLSClient) readNewSessionTicket(comKey []byte, trafficKey *trafficKeyPair) error {
	record, err := c.readRecord()
	if err != nil {
		return err
	}

	if err := record.decrypt(trafficKey, c.serverSeqNum); err != nil {
		return err
	}

	tickets, err := readNewSessionTicket(record.data)
	if err != nil {
		return err
	}

	pskAccess := make([]byte, 32)
	hkdf.Expand(
		sha256.New,
		comKey,
		c.hkdfExpand("PSK_ACCESS", c.handshakeHasher)).Read(pskAccess)
	log.Debugf("PSK_ACCESS:\n%s\n", hex.Dump(pskAccess))

	pskRefresh := make([]byte, 32)
	hkdf.Expand(
		sha256.New,
		comKey,
		c.hkdfExpand("PSK_REFRESH", c.handshakeHasher)).Read(pskRefresh)
	log.Debugf("PSK_REFRESH:\n%s\n", hex.Dump(pskRefresh))

	c.Session = &Session{
		tk:         tickets,
		pskAccess:  pskAccess,
		pskRefresh: pskRefresh,
	}

	c.handshakeHasher.Write(record.data)
	c.serverSeqNum++

	return nil
}

func (c *MMTLSClient) readServerFinish(comKey []byte, trafficKey *trafficKeyPair) error {
	record, err := c.readRecord()
	if err != nil {
		return err
	}

	if err := record.decrypt(trafficKey, c.serverSeqNum); err != nil {
		return err
	}

	sf, err := ReadServerFinish(record.data)
	if err != nil {
		return nil
	}

	sfKey := make([]byte, 32)
	hkdf.Expand(
		sha256.New,
		comKey,
		c.hkdfExpand("server finished", nil)).Read(sfKey)

	securityParam := c.hmac(sfKey, c.handshakeHasher.Sum(nil))

	if bytes.Compare(sf.data, securityParam) != 0 {
		return errors.New("security key not compare")
	}

	c.serverSeqNum++

	return nil
}

func (c *MMTLSClient) sendClientFinish(comKey []byte, trafficKey *trafficKeyPair) error {
	cliKey := make([]byte, 32)
	hkdf.Expand(
		sha256.New,
		comKey,
		c.hkdfExpand("client finished", nil)).Read(cliKey)
	cliKey = c.hmac(cliKey, c.handshakeHasher.Sum(nil))

	cf := newClientFinish(cliKey)

	cfRecord := createHandshakeRecord(cf.serialize())
	if err := cfRecord.encrypt(trafficKey, c.clientSeqNum); err != nil {
		return err
	}

	packet := cfRecord.serialize()
	log.Debugf("Send ClientFinish packet(%d):\n%s", len(packet), hex.Dump(packet))
	_, err := c.conn.Write(packet)

	c.clientSeqNum++

	return err
}

func (c *MMTLSClient) sendNoop() error {
	noop := createDataRecord(TCP_NoopRequest, 0xFFFFFFFF, nil)
	noop.encrypt(c.Session.appKey, c.clientSeqNum)

	packet := noop.serialize()
	log.Debugf("Send Noop packet(%d):\n%s", len(packet), hex.Dump(packet))
	_, err := c.conn.Write(packet)

	c.clientSeqNum++

	return err
}

func (c *MMTLSClient) readNoop() error {
	record, err := c.readRecord()
	if err != nil {
		return err
	}

	if err := record.decrypt(c.Session.appKey, c.serverSeqNum); err != nil {
		return err
	}

	r := bytes.NewReader(record.data)

	var packLen uint32
	if err := binary.Read(r, binary.BigEndian, &packLen); err != nil {
		return err
	}
	if packLen != 16 {
		return errors.New("noop response packet length invalid")
	}

	// skip flag
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return err
	}

	var dataType uint32
	if err := binary.Read(r, binary.BigEndian, &dataType); err != nil {
		return err
	}
	if TCP_NoopResponse != dataType {
		return errors.New("noop response packet type mismatch")
	}

	c.serverSeqNum++

	return nil
}

func (c *MMTLSClient) readRecord() (*mmtlsRecord, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return nil, err
	}

	packLen := binary.BigEndian.Uint16(header[3:])

	payload := make([]byte, packLen)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, err
	}

	log.Debugf("Receive Packet Header(%d):\n%s", len(header), hex.Dump(header))
	log.Debugf("Receive Packet payload(%d):\n%s", len(payload), hex.Dump(payload))

	record := readRecord(append(header, payload...))

	return record, nil
}

func (c *MMTLSClient) computeEphemeralSecret(x, y, z *big.Int) []byte {
	r, _ := curve.ScalarMult(x, y, z.Bytes())
	s := sha256.Sum256(r.Bytes())
	return s[:]
}

func (c *MMTLSClient) computeTrafficKey(shareKey, info []byte) (*trafficKeyPair, error) {
	trafficKey := make([]byte, 56)
	if _, err := hkdf.Expand(sha256.New, shareKey, info).Read(trafficKey); err != nil {
		return nil, err
	}

	log.Debugf("TrafficKey:\n%s\n", hex.Dump(trafficKey))

	pair := &trafficKeyPair{}
	pair.clientKey = trafficKey[:16]
	pair.serverKey = trafficKey[16:32]
	pair.clientNonce = trafficKey[32:44]
	pair.serverNonce = trafficKey[44:]

	return pair, nil
}

func (c *MMTLSClient) earlyDataKey(pskAccess []byte, st *newSessionTicket) (*trafficKeyPair, error) {
	earlyDataHash := sha256.New()
	data, err := st.export()
	if err != nil {
		return nil, err
	}
	if _, err := earlyDataHash.Write(data); err != nil {
		return nil, err
	}

	trafficKey := make([]byte, 28)
	if _, err := hkdf.Expand(sha256.New, pskAccess,
		c.hkdfExpand("early data key expansion", earlyDataHash)).
		Read(trafficKey); err != nil {
		return nil, err
	}

	// early data key expansion
	pair := &trafficKeyPair{}
	pair.clientKey = trafficKey[:16]
	pair.clientNonce = trafficKey[16:]

	return pair, nil
}

func (c *MMTLSClient) verifyEcdsa(data []byte) bool {
	dataHash := sha256.Sum256(c.handshakeHasher.Sum(nil))
	return ecdsa.VerifyASN1(ServerEcdh, dataHash[:], data)
}

func (c *MMTLSClient) hkdfExpand(prefix string, hash hash.Hash) []byte {
	info := []byte(prefix)
	if hash != nil {
		info = append(info, hash.Sum(nil)...)
	}
	return info
}

func (c *MMTLSClient) hmac(k []byte, d []byte) []byte {
	hm := hmac.New(sha256.New, k)
	hm.Write(d)
	return hm.Sum(nil)
}

func (c *MMTLSClient) genKeyPairs() error {
	if c.publicEcdh == nil {
		public, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		c.publicEcdh = public
	}

	if c.verifyEcdh == nil {
		verify, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		c.verifyEcdh = verify
	}

	return nil
}
