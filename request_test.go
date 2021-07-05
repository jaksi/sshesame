package main

import (
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testRequests(t *testing.T, dataDir string, cfg *config, clientAddress string) string {
	logBuffer := setupLogBuffer(t, cfg)

	conn, newChannels, requests, done := testClient(t, dataDir, cfg, clientAddress)
	defer conn.Close()

	channelTypes := []string{}
	channelsDone := make(chan interface{})
	go func() {
		for newChannel := range newChannels {
			channelTypes = append(channelTypes, newChannel.ChannelType())
		}
		channelsDone <- nil
	}()

	requestTypes := []string{}
	requestsDone := make(chan interface{})
	go func() {
		for request := range requests {
			requestTypes = append(requestTypes, request.Type)
		}
		requestsDone <- nil
	}()

	accepted, response, err := conn.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 0}))
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	if !accepted {
		t.Errorf("accepted=false, want true")
	}
	parsedResponse := struct{ Port uint32 }{}
	if err := ssh.Unmarshal(response, &parsedResponse); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if !(parsedResponse.Port >= 1024 && parsedResponse.Port <= 65535) {
		t.Errorf("parsedResponse.Port=%v, want between 1024 and 65535", parsedResponse.Port)
	}

	accepted, response, err = conn.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 1234}))
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	if !accepted {
		t.Errorf("accepted=false, want true")
	}
	if len(response) != 0 {
		t.Errorf("response=%v, want []", response)
	}

	accepted, response, err = conn.SendRequest("cancel-tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 0}))
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	if !accepted {
		t.Errorf("accepted=false, want true")
	}
	if len(response) != 0 {
		t.Errorf("response=%v, want []", response)
	}
	conn.Close()

	<-channelsDone
	<-requestsDone
	<-done

	expectedRequestTypes := []string{"hostkeys-00@openssh.com"}
	if !reflect.DeepEqual(requestTypes, expectedRequestTypes) {
		t.Errorf("requestTypes=%v, want %v", requestTypes, expectedRequestTypes)
	}

	if len(channelTypes) != 0 {
		t.Errorf("channelTypes=%v, want []", channelTypes)
	}

	return logBuffer.String()
}

func TestRequests(t *testing.T) {
	dataDir := t.TempDir()
	key, err := generateKey(dataDir, ecdsa_key)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cfg := &config{}
	cfg.Server.HostKeys = []string{key}
	cfg.Auth.NoAuth = true
	if err := cfg.setupSSHConfig(); err != nil {
		t.Fatalf("Failed to setup SSH config: %v", err)
	}

	clientAddress := path.Join(dataDir, "client.sock")

	logs := testRequests(t, dataDir, cfg, clientAddress)

	expectedLogs := fmt.Sprintf(`[%[1]v] authentication for user "" without credentials accepted
[%[1]v] connection with client version "SSH-2.0-Go" established
[%[1]v] TCP/IP forwarding on 127.0.0.1:0 requested
[%[1]v] TCP/IP forwarding on 127.0.0.1:1234 requested
[%[1]v] TCP/IP forwarding on 127.0.0.1:0 canceled
[%[1]v] connection closed
`, clientAddress)
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestRequestsJSON(t *testing.T) {
	dataDir := t.TempDir()
	key, err := generateKey(dataDir, ecdsa_key)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cfg := &config{}
	cfg.Server.HostKeys = []string{key}
	cfg.Logging.JSON = true
	cfg.Auth.NoAuth = true
	if err := cfg.setupSSHConfig(); err != nil {
		t.Fatalf("Failed to setup SSH config: %v", err)
	}

	clientAddress := path.Join(dataDir, "client.sock")

	logs := testRequests(t, dataDir, cfg, clientAddress)

	escapedClientAddress, err := json.Marshal(clientAddress)
	if err != nil {
		t.Fatalf("Failed to escape clientAddress: %v", err)
	}
	expectedLogs := fmt.Sprintf(`{"source":%[1]v,"event_type":"no_auth","event":{"user":"","accepted":true}}
{"source":%[1]v,"event_type":"connection","event":{"client_version":"SSH-2.0-Go"}}
{"source":%[1]v,"event_type":"tcpip_forward","event":{"address":"127.0.0.1:0"}}
{"source":%[1]v,"event_type":"tcpip_forward","event":{"address":"127.0.0.1:1234"}}
{"source":%[1]v,"event_type":"cancel_tcpip_forward","event":{"address":"127.0.0.1:0"}}
{"source":%[1]v,"event_type":"connection_close","event":{}}
`, string(escapedClientAddress))
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}
