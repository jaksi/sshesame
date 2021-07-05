package main

import (
	"bytes"
	"log"
	"net"
	"path"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testClient(t *testing.T, dataDir string, cfg *config, clientAddress string) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, <-chan interface{}) {
	serverAddress := path.Join(dataDir, "server.sock")
	listener, err := net.Listen("unix", serverAddress) // TODO: close
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan interface{})
	go func() {
		defer func() { serverDone <- nil }()
		serverConn, err := listener.Accept()
		if err != nil {
			t.Errorf("Failed to accept connection: %v", err)
			return
		}
		handleConnection(serverConn, cfg)
	}()

	clientConn, err := net.DialUnix("unix", &net.UnixAddr{Name: clientAddress, Net: "unix"}, &net.UnixAddr{Name: serverAddress, Net: "unix"})
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	clientSSHConn, newChannels, requests, err := ssh.NewClientConn(clientConn, clientAddress, &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		clientConn.Close()
		t.Fatalf("Failed to establish SSH connection: %v", err)
	}

	return clientSSHConn, newChannels, requests, serverDone
}

func setupLogBuffer(t *testing.T, cfg *config) *bytes.Buffer {
	if err := cfg.setupLogging(); err != nil {
		t.Fatalf("Failed to setup logging: %v", err)
	}
	buffer := &bytes.Buffer{}
	log.SetOutput(buffer)
	return buffer
}
