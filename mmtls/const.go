package mmtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

const (
	ProtocolVersion uint16 = 0xF104

	MagicAlert     uint8 = 0x15
	MagicHandshake uint8 = 0x16
	MagicRecord    uint8 = 0x17
)

const (
	TCP_NoopRequest  uint32 = 0x6
	TCP_NoopResponse uint32 = 0x3B9ACA06
)

var (
	ServerEcdh *ecdsa.PublicKey = &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     bigintFromHex("1da177b6a5ed34dabb3f2b047697ca8bbeb78c68389ced43317a298d77316d54"),
		Y:     bigintFromHex("4175c032bc573d5ce4b3ac0b7f2b9a8d48ca4b990ce2fa3ce75cc9d12720fa35"),
	}
)

func bigintFromHex(s string) *big.Int {
	b := big.NewInt(0)
	b.SetString(s, 16)
	return b
}
