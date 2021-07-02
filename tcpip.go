package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"

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

func (data tcpipChannelData) String() string {
	return fmt.Sprintf("%v -> %v", net.JoinHostPort(data.OriginatorAddress, fmt.Sprint(data.OriginatorPort)), net.JoinHostPort(data.Address, fmt.Sprint(data.Port)))
}

func handleDirectTCPIPChannel(newChannel ssh.NewChannel, metadata channelMetadata) error {
	channelData := &tcpipChannelData{}
	if err := ssh.Unmarshal(newChannel.ExtraData(), channelData); err != nil {
		return err
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	metadata.getLogEntry().WithField("channel_extra_data", channelData).Infoln("New channel accepted")
	defer metadata.getLogEntry().Infoln("Channel closed")

	server := servers[channelData.Port]
	if server == nil {
		log.Println("Unsupported port", channelData.Port)
		return nil
	}

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
			metadata.getLogEntry().WithField("input", input).Infoln("Channel input received")
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
