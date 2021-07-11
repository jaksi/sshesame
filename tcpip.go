package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"

	"golang.org/x/crypto/ssh"
)

type tcpipServer interface {
	serve(channel ssh.Channel, input chan<- string) error
}

var servers = map[uint32]tcpipServer{
	80: httpServer{},
}

type tcpipChannelData struct {
	Address           string
	Port              uint32
	OriginatorAddress string
	OriginatorPort    uint32
}

func handleDirectTCPIPChannel(newChannel ssh.NewChannel, context channelContext) error {
	channelData := &tcpipChannelData{}
	if err := ssh.Unmarshal(newChannel.ExtraData(), channelData); err != nil {
		return err
	}
	server := servers[channelData.Port]
	if server == nil {
		warningLogger.Printf("Unsupported port %v", channelData.Port)
		return newChannel.Reject(ssh.ConnectionFailed, "Connection refused")
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	context.logEvent(directTCPIPLog{
		channelLog: channelLog{
			ChannelID: context.channelID,
		},
		From: net.JoinHostPort(channelData.OriginatorAddress, strconv.Itoa(int(channelData.OriginatorPort))),
		To:   net.JoinHostPort(channelData.Address, strconv.Itoa(int(channelData.Port))),
	})
	defer context.logEvent(directTCPIPCloseLog{
		channelLog: channelLog{
			ChannelID: context.channelID,
		},
	})

	inputChan := make(chan string)
	errorChan := make(chan error)
	go func() {
		defer close(inputChan)
		defer close(errorChan)
		errorChan <- server.serve(channel, inputChan)
	}()

	for inputChan != nil || errorChan != nil || requests != nil {
		select {
		case input, ok := <-inputChan:
			if !ok {
				inputChan = nil
				continue
			}
			context.logEvent(directTCPIPInputLog{
				channelLog: channelLog{
					ChannelID: context.channelID,
				},
				Input: input,
			})
		case err, ok := <-errorChan:
			if !ok {
				errorChan = nil
				continue
			}
			if err != nil {
				return err
			}
		case request, ok := <-requests:
			if !ok {
				requests = nil
				continue
			}
			context.logEvent(debugChannelRequestLog{
				channelLog:  channelLog{ChannelID: context.channelID},
				RequestType: request.Type,
				WantReply:   request.WantReply,
				Payload:     string(request.Payload),
			})
			warningLogger.Printf("Unsupported direct-tcpip request type %v", request.Type)
			if request.WantReply {
				if err := request.Reply(false, nil); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

type httpServer struct{}

func (httpServer) serveRequest(channel ssh.Channel, input chan<- string) error {
	request, err := http.ReadRequest(bufio.NewReader(channel))
	if err != nil {
		return err
	}
	requestBytes, err := httputil.DumpRequest(request, true)
	if err != nil {
		return err
	}
	input <- string(requestBytes)
	_, err = channel.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	return err
}

func (server httpServer) serve(channel ssh.Channel, input chan<- string) error {
	var err error
	for err == nil {
		err = server.serveRequest(channel, input)
	}
	if err != nil && err != io.EOF {
		return err
	}
	if err = channel.CloseWrite(); err != nil {
		return err
	}
	return channel.Close()
}
