package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"

	"golang.org/x/crypto/ssh"
)

func handleDirectTCPIPChannel(channel ssh.Channel, port uint32) (string, error) {
	switch port {
	case 80:
		return handleHTTPChannel(channel)
	default:
		return "", fmt.Errorf("unsupported port %v", port)
	}
}

func handleHTTPChannel(channel ssh.Channel) (string, error) {
	request, err := http.ReadRequest(bufio.NewReader(channel))
	if err != nil {
		return "", err
	}
	requestBytes, err := httputil.DumpRequest(request, true)
	if err != nil {
		return "", err
	}
	responseRecorder := httptest.NewRecorder()
	http.NotFound(responseRecorder, request)
	if err := responseRecorder.Result().Write(channel); err != nil {
		return "", err
	}
	return string(requestBytes), nil
}
