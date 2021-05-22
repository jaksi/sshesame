package main

import (
	"fmt"
	"log"
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type tcpipRequestPayload struct {
	Address string
	Port    uint32
}

func (payload tcpipRequestPayload) String() string {
	return net.JoinHostPort(payload.Address, fmt.Sprint(payload.Port))
}

func handleGlobalRequests(requests <-chan *ssh.Request, conn ssh.ConnMetadata) {
	for request := range requests {
		if err := request.Reply(true, nil); err != nil {
			log.Println("Failed to accept global request:", err)
			continue
		}

		var requestPayload interface{}
		switch request.Type {
		case "tcpip-forward":
			fallthrough
		case "cancel-tcpip-forward":
			requestPayload = new(tcpipRequestPayload)
		default:
			log.Println("Unsupported global request type", request.Type)
			continue
		}
		requestPayloadString := ""
		if requestPayload != nil {
			if err := ssh.Unmarshal(request.Payload, requestPayload); err != nil {
				log.Println("Failed to parse request payload", err)
				continue
			}

			requestPayloadString = fmt.Sprint(requestPayload)
		}

		getLogEntry(conn).WithFields(logrus.Fields{
			"request_payload":    requestPayloadString,
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
