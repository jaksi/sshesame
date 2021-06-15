package main

import (
	"fmt"
	"io"
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

func handleTCPIPChannel(channel ssh.Channel, port uint32, input chan<- string) error {
	server := servers[port]
	if server == nil {
		return fmt.Errorf("unsupported port %v", port)
	}
	return server.handle(channelConn{channel}, input)
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
