package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"

	"golang.org/x/crypto/ssh"
)

type server interface {
	handle(channel ssh.Channel, input chan<- string) error
}

var servers = map[uint32]server{
	80: &httpServer{},
}

func handleTCPIPChannel(channel ssh.Channel, port uint32, input chan<- string) error {
	server := servers[port]
	if server == nil {
		return fmt.Errorf("unsupported port %v", port)
	}
	return server.handle(channel, input)
}

type httpServer struct{}

func (*httpServer) handle(channel ssh.Channel, input chan<- string) error {
	request, err := http.ReadRequest(bufio.NewReader(channel))
	if err != nil {
		return err
	}
	requestBytes, err := httputil.DumpRequest(request, true)
	if err != nil {
		return err
	}
	input <- string(requestBytes)
	responseRecorder := httptest.NewRecorder()
	http.NotFound(responseRecorder, request)
	if err := responseRecorder.Result().Write(channel); err != nil {
		return err
	}
	return nil
}
