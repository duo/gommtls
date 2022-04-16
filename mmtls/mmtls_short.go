package mmtls

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
)

type MMTLSClientShort struct {
	conn net.Conn

	status int32

	packetReader io.Reader

	handshakeHasher hash.Hash

	serverSeqNum uint32
	clientSeqNum uint32

	Session *Session
}

func NewMMTLSClientShort() *MMTLSClientShort {
	c := &MMTLSClientShort{}

	c.handshakeHasher = sha256.New()

	return c
}

func (c *MMTLSClientShort) Request(host, path string, req []byte) ([]byte, error) {
	log.Info("0-RTT PSK handshake")
	if c.Session == nil {
		return nil, errors.New("0-RTT requires session")
	}

	if c.conn == nil {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, 80))
		if err != nil {
			return nil, err
		}

		c.conn = conn
	}

	httpPacket, err := c.packHttp(host, path, req)
	if err != nil {
		return nil, err
	}

	_, err = c.conn.Write(httpPacket)

	response, err := c.parseResponse(c.conn)
	log.Debugf("Receive response:\n%s\n", hex.Dump(response))

	c.packetReader = bytes.NewReader(response)

	if err := c.readServerHello(); err != nil {
		return nil, err
	}

	// trafffic key
	trafficKey, err := c.computeTrafficKey(
		c.Session.pskAccess,
		c.hkdfExpand("handshake key expansion", c.handshakeHasher))
	if err != nil {
		return nil, err
	}
	c.Session.appKey = trafficKey

	if err := c.readServerFinish(); err != nil {
		return nil, err
	}

	dataRecord, err := c.readDataRecord()
	if err != nil {
		return nil, err
	}

	if err := c.readAbort(); err != nil {
		return nil, err
	}

	return dataRecord.data, nil
}

func (c *MMTLSClientShort) Close() error {
	if c.conn != nil {
		log.Debug("Close connection...")
		return c.conn.Close()
	}
	return nil
}

func (c *MMTLSClientShort) packHttp(host, path string, req []byte) ([]byte, error) {
	tlsPayload := make([]byte, 0)

	datPart, err := c.genDataPart(host, path, req)
	if err != nil {
		return nil, err
	}

	// ClientHello
	hello := newPskZeroHello(&c.Session.tk.tickets[0])
	helloPart := hello.serialize()

	c.handshakeHasher.Write(helloPart)

	earlyKey, _ := c.earlyDataKey(c.Session.pskAccess, &c.Session.tk.tickets[0])

	tlsPayload = append(tlsPayload, createSystemRecord(helloPart).serialize()...)
	c.clientSeqNum++

	// Extensions
	extensionsPart := []byte{
		0x00, 0x00, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00,
		0x0b, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x12,
		0x00, 0x00, 0x00, 0x00,
	}
	binary.BigEndian.PutUint32(extensionsPart[16:], hello.timestamp)

	c.handshakeHasher.Write(extensionsPart)

	extensionsRecord := createSystemRecord(extensionsPart)
	extensionsRecord.encrypt(earlyKey, c.clientSeqNum)

	tlsPayload = append(tlsPayload, extensionsRecord.serialize()...)
	c.clientSeqNum++

	// Request
	requestRecord := createRawDataRecord(datPart)
	requestRecord.encrypt(earlyKey, c.clientSeqNum)

	tlsPayload = append(tlsPayload, requestRecord.serialize()...)
	c.clientSeqNum++

	// Abort
	abortPart := []byte{0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01}
	abortRecord := createAbortRecord(abortPart)
	abortRecord.encrypt(earlyKey, c.clientSeqNum)

	tlsPayload = append(tlsPayload, abortRecord.serialize()...)
	c.clientSeqNum++

	// HTTP header
	header, err := c.buildRequestHeader(host, len(tlsPayload))
	if err != nil {
		return nil, err
	}

	return append(header, tlsPayload...), nil
}

func (c *MMTLSClientShort) genDataPart(host, path string, req []byte) ([]byte, error) {
	buf := &bytes.Buffer{}

	if err := writeU16LenData(buf, []byte(path)); err != nil {
		return nil, err
	}
	if err := writeU16LenData(buf, []byte(host)); err != nil {
		return nil, err
	}
	if err := writeU32LenData(buf, req); err != nil {
		return nil, err
	}

	data := buf.Bytes()
	pkt := make([]byte, 4)
	binary.BigEndian.PutUint32(pkt, uint32(len(data)))
	pkt = append(pkt, data...)

	return pkt, nil
}

func (c *MMTLSClientShort) buildRequestHeader(host string, length int) ([]byte, error) {
	request := &http.Request{
		Method:     http.MethodPost,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      false,
		Header:     map[string][]string{},
	}

	randName := make([]byte, 4)
	if _, err := rand.Read(randName); err != nil {
		return nil, err
	}

	request.Header.Set("Accept", "*/*")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Connection", "Keep-Alive")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Content-Length", fmt.Sprintf("%d", length))
	request.Header.Set("Upgrade", "mmtls")
	request.Header.Set("User-Agent", "MicroMessenger Client")
	request.URL, _ = url.Parse(fmt.Sprintf("https://%s/mmtls/%x", host, randName))

	b, err := httputil.DumpRequest(request, false)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (c *MMTLSClientShort) parseResponse(conn net.Conn) ([]byte, error) {
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err
	}

	b := new(bytes.Buffer)
	io.Copy(b, resp.Body)
	resp.Body.Close()
	resp.Body = ioutil.NopCloser(b)

	return b.Bytes(), nil
}

func (c *MMTLSClientShort) readServerHello() error {
	serverHelloRecord, err := readRecord(c.packetReader)
	if err != nil {
		return err
	}

	c.handshakeHasher.Write(serverHelloRecord.data)
	c.serverSeqNum++

	return nil
}

func (c *MMTLSClientShort) readServerFinish() error {
	record, err := readRecord(c.packetReader)
	if err != nil {
		return err
	}

	if err := record.decrypt(c.Session.appKey, c.serverSeqNum); err != nil {
		return err
	}

	// TODO: verify server finished
	c.serverSeqNum++

	return nil
}

func (c *MMTLSClientShort) readDataRecord() (*mmtlsRecord, error) {
	record, err := readRecord(c.packetReader)
	if err != nil {
		return nil, err
	}

	if err := record.decrypt(c.Session.appKey, c.serverSeqNum); err != nil {
		return nil, err
	}

	c.serverSeqNum++

	return record, nil
}

func (c *MMTLSClientShort) readAbort() error {
	record, err := readRecord(c.packetReader)
	if err != nil {
		return err
	}

	if err := record.decrypt(c.Session.appKey, c.serverSeqNum); err != nil {
		return err
	}

	c.serverSeqNum++

	return nil
}

func (c *MMTLSClientShort) earlyDataKey(pskAccess []byte, ticket *sessionTicket) (*trafficKeyPair, error) {
	trafficKey := make([]byte, 28)

	if _, err := hkdf.Expand(sha256.New, pskAccess,
		c.hkdfExpand("early data key expansion", c.handshakeHasher)).
		Read(trafficKey); err != nil {
		return nil, err
	}

	// early data key expansion
	pair := &trafficKeyPair{}
	pair.clientKey = trafficKey[:16]
	pair.clientNonce = trafficKey[16:]

	return pair, nil
}

func (c *MMTLSClientShort) computeTrafficKey(shareKey, info []byte) (*trafficKeyPair, error) {
	trafficKey := make([]byte, 28)

	if _, err := hkdf.Expand(sha256.New, shareKey,
		c.hkdfExpand("handshake key expansion", c.handshakeHasher)).
		Read(trafficKey); err != nil {
		return nil, err
	}

	// handshake key expansion
	pair := &trafficKeyPair{}
	pair.serverKey = trafficKey[:16]
	pair.serverNonce = trafficKey[16:]

	return pair, nil
}

func (c *MMTLSClientShort) hkdfExpand(prefix string, hash hash.Hash) []byte {
	info := []byte(prefix)
	if hash != nil {
		info = append(info, hash.Sum(nil)...)
	}
	return info
}

func (c *MMTLSClientShort) hmac(k []byte, d []byte) []byte {
	hm := hmac.New(sha256.New, k)
	hm.Write(d)
	return hm.Sum(nil)
}
