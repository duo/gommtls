package main

import (
	"github.com/duo/gommtls/mmtls"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(log.DebugLevel)

	client := mmtls.NewMMTLSClient()

	defer client.Close()

	if err := client.Handshake("long.weixin.qq.com:80"); err != nil {
		panic(err)
	}

	if err := client.Noop(); err != nil {
		panic(err)
	}
}
