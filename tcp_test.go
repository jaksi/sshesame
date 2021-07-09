package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testTCP(t *testing.T, dataDir string, cfg *config, clientAddress string) string {
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

	channel, channelRequests, err := conn.OpenChannel("direct-tcpip", ssh.Marshal(struct {
		Address           string
		Port              uint32
		OriginatorAddress string
		OriginatorPort    uint32
	}{"example.org", 80, "localhost", 8080}))
	if err != nil {
		t.Fatalf("Failed to open channel: %v", err)
	}
	if _, err := channel.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("Faield to write to channel: %v", err)
	}
	if err := channel.CloseWrite(); err != nil {
		t.Fatalf("Failed to close channel: %v", err)
	}
	channelRequestTypes := []string{}
	channelRequestsDone := make(chan interface{})
	go func() {
		for request := range channelRequests {
			channelRequestTypes = append(channelRequestTypes, request.Type)
		}
		channelRequestsDone <- nil
	}()

	channelResponse, err := ioutil.ReadAll(channel)
	if err != nil {
		t.Fatalf("Failed to read channel: %v", err)
	}
	expectedChannelResponse := "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
	if string(channelResponse) != expectedChannelResponse {
		t.Errorf("channelResponse=%v, want %v", string(channelResponse), expectedChannelResponse)
	}

	<-channelRequestsDone
	if len(channelRequestTypes) != 0 {
		t.Errorf("channelRequestTypes=%v, want []", channelRequestTypes)
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

func TestTCP(t *testing.T) {
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

	logs := testTCP(t, dataDir, cfg, clientAddress)

	expectedLogs := fmt.Sprintf(`[%[1]v] authentication for user "" without credentials accepted
[%[1]v] connection with client version "SSH-2.0-Go" established
[%[1]v] [channel 0] direct TCP/IP forwarding from localhost:8080 to example.org:80 requested
[%[1]v] [channel 0] input: "GET / HTTP/1.1\r\n\r\n"
[%[1]v] [channel 0] closed
[%[1]v] connection closed
`, clientAddress)
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestTCPJSON(t *testing.T) {
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

	logs := testTCP(t, dataDir, cfg, clientAddress)
	escapedClientAddress, err := json.Marshal(clientAddress)
	if err != nil {
		t.Fatalf("Failed to escape clientAddress: %v", err)
	}

	expectedLogs := fmt.Sprintf(`{"source":%[1]v,"event_type":"no_auth","event":{"user":"","accepted":true}}
{"source":%[1]v,"event_type":"connection","event":{"client_version":"SSH-2.0-Go"}}
{"source":%[1]v,"event_type":"direct_tcpip","event":{"channel_id":0,"from":"localhost:8080","to":"example.org:80"}}
{"source":%[1]v,"event_type":"direct_tcpip_input","event":{"channel_id":0,"input":"GET / HTTP/1.1\r\n\r\n"}}
{"source":%[1]v,"event_type":"direct_tcpip_close","event":{"channel_id":0}}
{"source":%[1]v,"event_type":"connection_close","event":{}}
`, string(escapedClientAddress))
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}
