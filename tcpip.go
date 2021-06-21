package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/ssh"
)

type channelConn struct {
	ssh.Channel
}

func (conn channelConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (conn channelConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (conn channelConn) SetDeadline(t time.Time) error {
	return nil
}

func (conn channelConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (conn channelConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type server interface {
	handle(conn channelConn, input chan<- string) error
}

var servers = map[uint32]server{
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
	defer channel.Close()
	metadata.getLogEntry().WithField("channel_extra_data", channelData).Infoln("New channel accepted")
	defer metadata.getLogEntry().Infoln("Channel closed")

	go func() {
		for request := range requests {
			if request.WantReply {
				if err := request.Reply(false, nil); err != nil {
					log.Println("Failed to reject direct-tcpip request:", err)
					channel.Close()
					return
				}
			}
		}
	}()

	server := servers[channelData.Port]
	if server == nil {
		return fmt.Errorf("unsupported port %v", channelData.Port)
	}
	inputChan := make(chan string)
	defer close(inputChan)
	go func() {
		for input := range inputChan {
			metadata.getLogEntry().WithField("input", input).Infoln("Channel input received")
		}
	}()
	return server.handle(channelConn{channel}, inputChan)
}

type httpServer struct{}

func (httpServer) handle(conn channelConn, input chan<- string) error {
	server := fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			input <- ctx.Request.String()
			ctx.SetStatusCode(404)
		},
		NoDefaultServerHeader: true,
		NoDefaultDate:         true,
		NoDefaultContentType:  true,
	}
	for {
		if err := server.ServeConn(conn); err != nil {
			if err != io.EOF {
				return err
			}
			return nil
		}
	}
}
