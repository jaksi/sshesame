package main

import (
	"math/rand"
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"
)

type request interface {
	name() string
	wantReply() bool
	payload() []byte
	reply(ok bool, payload []byte) error
}

type sshRequest struct {
	*ssh.Request
}

func (req sshRequest) name() string {
	return req.Type
}

func (req sshRequest) wantReply() bool {
	return req.WantReply
}

func (req sshRequest) payload() []byte {
	return req.Payload
}

func (req sshRequest) reply(ok bool, payload []byte) error {
	return req.Reply(ok, payload)
}

type globalRequestPayload interface {
	reply() []byte
	logEntry() logEntry
}

type globalRequestPayloadParser func(data []byte) (globalRequestPayload, error)

type channelRequestPayload interface {
	reply() []byte
	logEntry(channelID int) logEntry
}

type channelRequestPayloadParser func(data []byte) (channelRequestPayload, error)

type tcpipRequest struct {
	Address string
	Port    uint32
}

func (request tcpipRequest) reply() []byte {
	if request.Port != 0 {
		return nil
	}
	return ssh.Marshal(struct{ port uint32 }{uint32(rand.Intn(65536-1024) + 1024)})
}
func (request tcpipRequest) logEntry() logEntry {
	return tcpipForwardLog{
		Address: net.JoinHostPort(request.Address, strconv.Itoa(int(request.Port))),
	}
}

type cancelTCPIPRequest struct {
	Address string
	Port    uint32
}

func (request cancelTCPIPRequest) reply() []byte {
	return nil
}
func (request cancelTCPIPRequest) logEntry() logEntry {
	return cancelTCPIPForwardLog{
		Address: net.JoinHostPort(request.Address, strconv.Itoa(int(request.Port))),
	}
}

var globalRequestPayloads = map[string]globalRequestPayloadParser{
	"tcpip-forward": func(data []byte) (globalRequestPayload, error) {
		payload := &tcpipRequest{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"cancel-tcpip-forward": func(data []byte) (globalRequestPayload, error) {
		payload := &cancelTCPIPRequest{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
}

func handleGlobalRequest(req request, metadata connMetadata) error {
	parser := globalRequestPayloads[req.name()]
	if parser == nil {
		warningLogger.Printf("Unsupported global request type %v", req.name())
		if req.wantReply() {
			if err := req.reply(false, nil); err != nil {
				return err
			}
		}
		return nil
	}
	payload, err := parser(req.payload())
	if err != nil {
		return err
	}
	if req.wantReply() {
		if err := req.reply(true, payload.reply()); err != nil {
			return err
		}
	}
	metadata.logEvent(payload.logEntry())
	return nil
}

func createHostkeysRequestPayload(keys []ssh.Signer) []byte {
	result := make([]byte, 0)
	for _, key := range keys {
		result = append(result, ssh.Marshal(struct{ key string }{string(key.PublicKey().Marshal())})...)
	}
	return result
}
