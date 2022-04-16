package main

import (
	"encoding/hex"

	"github.com/duo/gommtls/mmtls"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(log.DebugLevel)

	{
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

	{
		client := mmtls.NewMMTLSClientShort()

		if session, err := mmtls.LoadSession("session"); err == nil {
			client.Session = session
		}

		defer client.Close()

		response, err := client.Request(
			"dns.weixin.qq.com.cn",
			"/cgi-bin/micromsg-bin/newgetdns",
			nil,
		)
		if err != nil {
			panic(err)
		}

		log.Debugf("Response:\n%s\n", hex.Dump(response))
	}
}
