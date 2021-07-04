package main

import (
	"net"
	"path"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestHandleConnection(t *testing.T) {
	dataDir := t.TempDir()
	key := pkcs8fileKey{}
	hostKey, err := key.generate(dataDir, ecdsa_key)
	if err != nil {
		t.Fatalf("Failed to generate host key: %v", err)
	}
	cfg := &config{
		Server: serverConfig{HostKeys: []string{hostKey}},
		Auth:   authConfig{NoAuth: true},
	}
	if err := cfg.setupSSHConfig(key); err != nil {
		t.Fatalf("Failed to setup SSH config: %v", err)
	}
	cfg.sshConfig.AddHostKey(mockSigner{signature: ecdsa_key})
	address := path.Join(t.TempDir(), "test.sock")
	listener, err := net.Listen("unix", address)
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
	clientConn, err := net.Dial("unix", address)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()
	clientSSHConn, channels, requests, err := ssh.NewClientConn(clientConn, "127.0.0.1:2022", &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Errorf("Failed to create client connection: %v", err)
		return
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
	_, _, _ = clientSSHConn.SendRequest("test", false, nil)
	_, _, _ = clientSSHConn.OpenChannel("test", nil)
	channel, _, err := clientSSHConn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("Failed to request session channel: %v", err)
	}
	if channel.Close() != nil {
		t.Fatalf("Faield to close session channel: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	channel, _, err = clientSSHConn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("Failed to request session channel: %v", err)
	}
	if channel.Close() != nil {
		t.Fatalf("Faield to close session channel: %v", err)
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
	logs := logBuffer.String()
	expectedLogs := `[] authentication for user "" without credentials accepted
[] connection with client version "SSH-2.0-Go" established
[] [channel 0] session requested
[] [channel 0] closed
[] [channel 1] session requested
[] [channel 1] closed
[] connection closed
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}
