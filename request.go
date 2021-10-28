package main

import (
	cryptoRand "crypto/rand"
	"errors"
	mathRand "math/rand"
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/ssh"
)

type globalRequestPayload interface {
	reply(context *connContext) []byte
	logEntry(context *connContext) logEntry
}

type globalRequestPayloadParser func(data []byte) (globalRequestPayload, error)

type tcpipRequest struct {
	Address string
	Port    uint32
}

func (request tcpipRequest) reply(context *connContext) []byte {
	if request.Port != 0 {
		return nil
	}
	return ssh.Marshal(struct{ port uint32 }{uint32(mathRand.Intn(65536-1024) + 1024)})
}
func (request tcpipRequest) logEntry(context *connContext) logEntry {
	return tcpipForwardLog{
		Address: net.JoinHostPort(request.Address, strconv.Itoa(int(request.Port))),
	}
}

type cancelTCPIPRequest struct {
	Address string
	Port    uint32
}

func (request cancelTCPIPRequest) reply(context *connContext) []byte {
	return nil
}
func (request cancelTCPIPRequest) logEntry(context *connContext) logEntry {
	return cancelTCPIPForwardLog{
		Address: net.JoinHostPort(request.Address, strconv.Itoa(int(request.Port))),
	}
}

type noMoreSessionsRequest struct {
}

func (request noMoreSessionsRequest) reply(context *connContext) []byte {
	return nil
}
func (request noMoreSessionsRequest) logEntry(context *connContext) logEntry {
	return noMoreSessionsLog{}
}

type hostKeysProveRequest struct {
	hostKeyIndices []int
}

func (request hostKeysProveRequest) reply(context *connContext) []byte {
	signatures := make([][]byte, len(request.hostKeyIndices))
	for i, index := range request.hostKeyIndices {
		signature, err := context.cfg.parsedHostKeys[index].Sign(cryptoRand.Reader, ssh.Marshal(struct {
			requestType, sessionID, hostKey string
		}{
			"hostkeys-prove-00@openssh.com",
			string(context.SessionID()),
			string(context.cfg.parsedHostKeys[index].PublicKey().Marshal()),
		}))
		if err != nil {
			warningLogger.Printf("Failed to sign host key: %v", err)
			return nil
		}
		signatures[i] = ssh.Marshal(signature)
	}
	return marshalBytes(signatures)
}
func (request hostKeysProveRequest) logEntry(context *connContext) logEntry {
	hostKeyFiles := make([]string, len(request.hostKeyIndices))
	for i, index := range request.hostKeyIndices {
		hostKeyFiles[i] = context.cfg.Server.HostKeys[index]
	}
	return hostKeysProveLog{
		HostKeyFiles: hostKeyFiles,
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
	"no-more-sessions@openssh.com": func(data []byte) (globalRequestPayload, error) {
		if len(data) != 0 {
			return nil, errors.New("invalid request payload")
		}
		return &noMoreSessionsRequest{}, nil
	},
}

var (
	globalRequestsMetric = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sshesame_global_requests_total",
		Help: "Total number of global requests",
	}, []string{"type"})
)

func handleGlobalRequest(request *ssh.Request, context *connContext) error {
	parser := globalRequestPayloads[request.Type]
	if parser == nil {
		globalRequestsMetric.WithLabelValues("unknown").Inc()
		warningLogger.Printf("Unsupported global request type %v", request.Type)
		if request.WantReply {
			if err := request.Reply(false, nil); err != nil {
				return err
			}
		}
		return nil
	}
	globalRequestsMetric.WithLabelValues(request.Type).Inc()
	payload, err := parser(request.Payload)
	if err != nil {
		return err
	}
	switch payload.(type) {
	case *noMoreSessionsRequest:
		context.noMoreSessions = true
	}
	if request.WantReply {
		if err := request.Reply(true, payload.reply(context)); err != nil {
			return err
		}
	}
	context.logEvent(payload.logEntry(context))
	return nil
}

func marshalBytes(data [][]byte) []byte {
	var result []byte
	for _, b := range data {
		result = append(result, ssh.Marshal(struct{ string }{string(b)})...)
	}
	return result
}
