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

	if session, err := mmtls.LoadSession("session"); err == nil {
		client.Session = session
	}

	if err := client.Handshake("long.weixin.qq.com:80"); err != nil {
		panic(err)
	}

	if client.Session != nil {
		client.Session.Save("session")
	}

	if err := client.Noop(); err != nil {
		panic(err)
	}
}
