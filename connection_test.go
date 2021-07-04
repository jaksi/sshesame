package main

import (
	"fmt"
	"io"
	"net"
	"path"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type testRequest struct {
	name    string
	data    []byte
	success bool
}

type channelResult int

const (
	rejected channelResult = iota
	accepted
	failed
)

type testChannel struct {
	name   string
	data   []byte
	result channelResult
}

func testConnection(t *testing.T, clientAddress string, clientRequests []testRequest, clientChannels []testChannel) string {
	hostKey, err := generateKey(t.TempDir(), ecdsa_key)
	if err != nil {
		t.Fatalf("Failed to generate host key: %v", err)
	}
	cfg := &config{
		Server: serverConfig{HostKeys: []string{hostKey}},
		Auth:   authConfig{NoAuth: true},
	}
	if err := cfg.setupSSHConfig(); err != nil {
		t.Fatalf("Failed to setup SSH config: %v", err)
	}
	cfg.sshConfig.AddHostKey(mockSigner{signature: ecdsa_key})
	tempDir := t.TempDir()
	serverAddress := path.Join(tempDir, "server.sock")
	listener, err := net.Listen("unix", serverAddress)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()
	resultChan := make(chan interface{})
	logBuffer := setupLogBuffer(cfg)
	go func() {
		defer func() { resultChan <- nil }()
		serverConn, err := listener.Accept()
		if err != nil {
			t.Errorf("Failed to accept conenction: %v", err)
			return
		}
		handleConnection(serverConn, cfg)
	}()
	clientConn, err := net.DialUnix("unix", &net.UnixAddr{Name: clientAddress, Net: "unix"}, &net.UnixAddr{Name: serverAddress, Net: "unix"})
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()
	clientSSHConn, channels, requests, err := ssh.NewClientConn(clientConn, "127.0.0.1:2022", &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("Failed to create client connection: %v", err)
	}
	requestTypes := []string{}
	channelTypes := []string{}
	requestsDone := make(chan interface{})
	go func() {
		for request := range requests {
			requestTypes = append(requestTypes, request.Type)
		}
		requestsDone <- nil
	}()
	channelsDone := make(chan interface{})
	go func() {
		for channel := range channels {
			channelTypes = append(channelTypes, channel.ChannelType())
		}
		channelsDone <- nil
	}()
	for _, clientRequest := range clientRequests {
		_, _, _ = clientSSHConn.SendRequest(clientRequest.name, false, clientRequest.data)
		if !clientRequest.success {
			if err := clientSSHConn.Wait(); err != io.EOF {
				t.Errorf("err=%v, want io.EOF", err)
			}
		}
	}
	for _, clientChannel := range clientChannels {
		channel, _, err := clientSSHConn.OpenChannel(clientChannel.name, clientChannel.data)
		switch clientChannel.result {
		case accepted:
			if err != nil {
				t.Fatalf("Failed to request channel: %v", err)
			}
			if err := channel.Close(); err != nil {
				t.Fatalf("Failed to close channel: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		case failed:
			if err := clientSSHConn.Wait(); err != io.EOF {
				t.Errorf("err=%v, want io.EOF", err)
			}
		}
	}
	clientSSHConn.Close()
	<-resultChan
	<-channelsDone
	<-requestsDone
	expectedRequests := []string{"hostkeys-00@openssh.com"}
	if !reflect.DeepEqual(requestTypes, expectedRequests) {
		t.Errorf("requestTypes=%v, want %v", requestTypes, expectedRequests)
	}
	if len(channelTypes) != 0 {
		t.Errorf("len(channelTypes)=%v, want 0", len(channelTypes))
	}
	return logBuffer.String()
}

func TestHandleConnection(t *testing.T) {
	clientAddress := path.Join(t.TempDir(), "client.sock")
	logs := testConnection(t, clientAddress, []testRequest{{"test", nil, true}, {"test", nil, true}}, []testChannel{{"test", nil, rejected}, {"session", nil, accepted}, {"session", nil, accepted}})
	expectedLogs := fmt.Sprintf(`[%[1]v] authentication for user "" without credentials accepted
[%[1]v] connection with client version "SSH-2.0-Go" established
[%[1]v] [channel 0] session requested
[%[1]v] [channel 0] closed
[%[1]v] [channel 1] session requested
[%[1]v] [channel 1] closed
[%[1]v] connection closed
`, clientAddress)
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestFailedRequestHandling(t *testing.T) {
	clientAddress := path.Join(t.TempDir(), "client.sock")
	logs := testConnection(t, clientAddress, []testRequest{{"tcpip-forward", nil, false}}, []testChannel{})
	expectedLogs := fmt.Sprintf(`[%[1]v] authentication for user "" without credentials accepted
[%[1]v] connection with client version "SSH-2.0-Go" established
[%[1]v] connection closed
`, clientAddress)
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestFailedChannelHandling(t *testing.T) {
	clientAddress := path.Join(t.TempDir(), "client.sock")
	logs := testConnection(t, clientAddress, []testRequest{}, []testChannel{{"direct-tcpip", nil, failed}})
	expectedLogs := fmt.Sprintf(`[%[1]v] authentication for user "" without credentials accepted
[%[1]v] connection with client version "SSH-2.0-Go" established
[%[1]v] connection closed
`, clientAddress)
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}
