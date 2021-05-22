package main

import (
	"log"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func handleGlobalRequests(requests <-chan *ssh.Request, conn ssh.ConnMetadata) {
	for request := range requests {
		if err := request.Reply(true, nil); err != nil {
			log.Println("Failed to accept global request:", err)
			continue
		}

		getLogEntry(conn).WithFields(logrus.Fields{
			"request_payload":    request.Payload,
			"request_type":       request.Type,
			"request_want_reply": request.WantReply,
		}).Infoln("Global request accepted")
	}
}

func handleChannelRequests(requests <-chan *ssh.Request, conn channelMetadata) {
	for request := range requests {
		if err := request.Reply(true, nil); err != nil {
			log.Println("Failed to accept channel request:", err)
			continue
		}

		conn.getLogEntry().WithFields(logrus.Fields{
			"request_payload":    request.Payload,
			"request_type":       request.Type,
			"request_want_reply": request.WantReply,
		}).Infoln("Channel request accepted")
	}
}
