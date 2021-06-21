package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type requestPayload fmt.Stringer

type requestPayloadParser func(data []byte) (requestPayload, error)

type tcpipRequestPayload struct {
	Address string
	Port    uint32
}

func (payload tcpipRequestPayload) String() string {
	return net.JoinHostPort(payload.Address, fmt.Sprint(payload.Port))
}

var globalRequestPayloadParsers = map[string]requestPayloadParser{
	"tcpip-forward": func(data []byte) (requestPayload, error) {
		payload := &tcpipRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"cancel-tcpip-forward": func(data []byte) (requestPayload, error) {
		payload := &tcpipRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
}

func handleGlobalRequest(request *ssh.Request, metadata connMetadata) error {
	var payload requestPayload
	parser := globalRequestPayloadParsers[request.Type]
	if parser == nil {
		log.Println("Unsupported global request type", request.Type)
		if request.WantReply {
			if err := request.Reply(false, nil); err != nil {
				return err
			}
		}
		return nil
	}
	payload, err := parser(request.Payload)
	if err != nil {
		return err
	}
	metadata.getLogEntry().WithFields(logrus.Fields{
		"request_payload":    payload,
		"request_type":       request.Type,
		"request_want_reply": request.WantReply,
	}).Infoln("Global request accepted")
	if request.WantReply {
		var response []byte
		switch request.Type {
		case "tcpip-forward":
			if payload.(*tcpipRequestPayload).Port == 0 {
				response = ssh.Marshal(struct{ port uint32 }{uint32(rand.Intn(65536-1024) + 1024)})
			}
		}
		if err := request.Reply(true, response); err != nil {
			return err
		}
	}
	return nil
}

func createHostkeysRequestPayload(keys []ssh.Signer) []byte {
	result := make([]byte, 0)
	for _, key := range keys {
		result = append(result, ssh.Marshal(struct{ key string }{string(key.PublicKey().Marshal())})...)
	}
	return result
}
