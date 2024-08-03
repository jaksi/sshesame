package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jaksi/sshutils"
	"golang.org/x/crypto/ssh"
)

type replayTest struct {
	User      string                   `json:"user"`
	Events    []replayTestEvent        `json:"events"`
	PlainLogs []string                 `json:"plain_logs"`
	JSONLogs  []map[string]interface{} `json:"json_logs"`
}

type replayTestEvent struct {
	Source source          `json:"source"`
	Type   string          `json:"type"`
	Entry  replayTestEntry `json:"entry"`
}

func (event *replayTestEvent) UnmarshalJSON(data []byte) error {
	var rawEvent struct {
		Source source      `json:"source"`
		Type   string      `json:"type"`
		Entry  interface{} `json:"entry"`
	}
	if err := json.Unmarshal(data, &rawEvent); err != nil {
		return err
	}
	event.Source = rawEvent.Source
	event.Type = rawEvent.Type
	entryData, err := json.Marshal(rawEvent.Entry)
	if err != nil {
		return err
	}
	var entry replayTestEntry
	switch rawEvent.Type {
	case "global_request":
		entry = &globalRequestReplayEntry{}
	case "new_channel":
		entry = &newChannelReplayEntry{}
	case "channel_data":
		entry = &channelDataReplayEntry{}
	case "channel_eof":
		entry = &channelEOFReplayEntry{}
	case "channel_close":
		entry = &channelCloseReplayEntry{}
	case "connection_close":
		entry = &connectionCloseReplayEntry{}
	case "channel_request":
		entry = &channelRequestReplayEntry{}
	case "channel_error":
		entry = &channelErrorReplayEntry{}
	default:
		return fmt.Errorf("unsuported event type %s", event.Type)
	}
	if err = json.Unmarshal(entryData, &entry); err != nil {
		return err
	}
	event.Entry = entry
	return nil
}

type source int

const (
	client source = iota
	server
)

func (src source) String() string {
	switch src {
	case client:
		return "client"
	case server:
		return "server"
	default:
		return "unknown"
	}
}

func (src *source) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case `"client"`:
		*src = client
	case `"server"`:
		*src = server
	default:
		return fmt.Errorf("unknown source: %q", string(data))
	}
	return nil
}

type replayTestEntry interface {
	Execute(t *testing.T, context *clientContext) error
	Wait(t *testing.T, context *clientContext) error
}

type clientChannel struct {
	channel  ssh.Channel
	requests <-chan *ssh.Request
}

type clientContext struct {
	conn           ssh.Conn
	requests       <-chan *ssh.Request
	channels       <-chan ssh.NewChannel
	clientChannels []clientChannel
}

type globalRequestReplayEntry struct {
	Type      string `json:"type"`
	WantReply bool   `json:"want_reply"`
	Payload   string `json:"payload"`

	Accepted bool   `json:"accepted"`
	Response string `json:"response"`
}

func (event globalRequestReplayEntry) Execute(t *testing.T, context *clientContext) error {
	rawPayload, err := base64.RawStdEncoding.DecodeString(event.Payload)
	if err != nil {
		return err
	}
	accepted, response, err := context.conn.SendRequest(event.Type, event.WantReply, rawPayload)
	if err != nil {
		return err
	}
	if accepted != event.Accepted {
		t.Errorf("Accepted mismatch: got %v, want %v", accepted, event.Accepted)
	}
	if event.Type != "tcpip-forward" {
		encodedResponse := base64.RawStdEncoding.EncodeToString(response)
		if encodedResponse != event.Response {
			t.Errorf("Response mismatch: got %v, want %v", encodedResponse, event.Response)
		}
	}
	return nil
}

func (event globalRequestReplayEntry) Wait(t *testing.T, context *clientContext) error {
	rawResponse, err := base64.RawStdEncoding.DecodeString(event.Response)
	if err != nil {
		return err
	}
	select {
	case request, ok := <-context.requests:
		if !ok {
			return fmt.Errorf("Connection was closed")
		}
		if request.WantReply {
			if err := request.Reply(event.Accepted, rawResponse); err != nil {
				return err
			}
		}
		if request.Type != event.Type {
			t.Errorf("Type mismatch: got %v, want %v", request.Type, event.Type)
		}
		if request.WantReply != event.WantReply {
			t.Errorf("WantReply mismatch: got %v, want %v", request.WantReply, event.WantReply)
		}
		if request.Type != "hostkeys-00@openssh.com" {
			encodedPayload := base64.RawStdEncoding.EncodeToString(request.Payload)
			if encodedPayload != event.Payload {
				t.Errorf("Payload mismatch: got %v, want %v", encodedPayload, event.Payload)
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timed out waiting for request")
	}
	return nil
}

type newChannelReplayEntry struct {
	Type      string `json:"type"`
	ExtraData string `json:"extra_data"`

	Accepted     bool   `json:"accepted"`
	RejectReason uint32 `json:"reject_reason"`
	Message      string `json:"message"`
}

func (event newChannelReplayEntry) Execute(t *testing.T, context *clientContext) error {
	rawExtraData, err := base64.RawStdEncoding.DecodeString(event.ExtraData)
	if err != nil {
		return err
	}
	channel, requests, err := context.conn.OpenChannel(event.Type, rawExtraData)
	accepted := true
	if openChannelErr, ok := err.(*ssh.OpenChannelError); ok {
		accepted = false
		if uint32(openChannelErr.Reason) != event.RejectReason {
			t.Errorf("Reject reason mismatch: got %v, want %v", uint32(openChannelErr.Reason), event.RejectReason)
		}
		if openChannelErr.Message != event.Message {
			t.Errorf("Message mismatch: got %q, want %q", openChannelErr.Message, event.Message)
		}
	} else if err != nil {
		return err
	}
	if accepted != event.Accepted {
		t.Errorf("Accepted mismatch: got %v, want %v", accepted, event.Accepted)
	}
	if accepted {
		context.clientChannels = append(context.clientChannels, clientChannel{channel, requests})
	}
	return nil
}

func (event newChannelReplayEntry) Wait(t *testing.T, context *clientContext) error {
	select {
	case newChannel, ok := <-context.channels:
		if !ok {
			return fmt.Errorf("Connection was closed")
		}
		if event.Accepted {
			channel, requests, err := newChannel.Accept()
			if err != nil {
				return err
			}
			context.clientChannels = append(context.clientChannels, clientChannel{channel, requests})
		} else {
			if err := newChannel.Reject(ssh.RejectionReason(event.RejectReason), event.Message); err != nil {
				return err
			}
		}
		if newChannel.ChannelType() != event.Type {
			t.Errorf("Type mismatch: got %v, want %v", newChannel.ChannelType(), event.Type)
		}
		encodedExtraData := base64.RawStdEncoding.EncodeToString(newChannel.ExtraData())
		if encodedExtraData != event.ExtraData {
			t.Errorf("ExtraData mismatch: got %v, want %v", encodedExtraData, event.ExtraData)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timed out waiting for channel")
	}
	return nil
}

type channelDataReplayEntry struct {
	ChannelID int    `json:"channel_id"`
	Data      string `json:"data"`
}

type readWriteResult struct {
	n   int
	err error
}

func (event channelDataReplayEntry) Execute(t *testing.T, context *clientContext) error {
	data := make(chan readWriteResult)
	go func() {
		n, err := context.clientChannels[event.ChannelID].channel.Write([]byte(event.Data))
		data <- readWriteResult{n, err}
	}()
	select {
	case result := <-data:
		if result.err != nil {
			return result.err
		}
		if result.n != len(event.Data) {
			t.Errorf("Wrote %d bytes, want %d", result.n, len(event.Data))
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timed out writing to channel")
	}
	return nil
}

func (event channelDataReplayEntry) Wait(t *testing.T, context *clientContext) error {
	buffer := make([]byte, len(event.Data))
	data := make(chan readWriteResult)
	go func() {
		var result readWriteResult
		for result.n < len(event.Data) {
			n, err := context.clientChannels[event.ChannelID].channel.Read(buffer[result.n:])
			result.n += n
			result.err = err
			if err != nil || n == 0 {
				break
			}
		}
		data <- result
	}()
	select {
	case result := <-data:
		if result.err != nil {
			return result.err
		}
		if result.n != len(event.Data) {
			t.Errorf("Read %d bytes, want %d", result.n, len(event.Data))
		}
		if string(buffer[:result.n]) != event.Data {
			t.Errorf("Data mismatch: got %q, want %q", string(buffer[:result.n]), event.Data)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timed out reading from channel. Data so far: %q, want %q", string(buffer), event.Data)
	}
	return nil
}

type channelEOFReplayEntry struct {
	ChannelID int `json:"channel_id"`
}

func (event channelEOFReplayEntry) Execute(t *testing.T, context *clientContext) error {
	if err := context.clientChannels[event.ChannelID].channel.CloseWrite(); err != nil {
		if err == io.EOF {
			t.Errorf("Channel already closed for writing")
		} else {
			return err
		}
	}
	return nil
}

func (event channelEOFReplayEntry) Wait(t *testing.T, context *clientContext) error {
	buffer := make([]byte, 256)
	n, err := context.clientChannels[event.ChannelID].channel.Read(buffer)
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	t.Errorf("Read %q, want EOF", string(buffer[:n]))
	return nil
}

type channelCloseReplayEntry struct {
	ChannelID int `json:"channel_id"`
}

func (event channelCloseReplayEntry) Execute(t *testing.T, context *clientContext) error {
	if err := context.clientChannels[event.ChannelID].channel.Close(); err != nil {
		if err == io.EOF {
			t.Errorf("Channel already closed")
		} else {
			return err
		}
	}
	return nil
}

func (event channelCloseReplayEntry) Wait(t *testing.T, context *clientContext) error {
	select {
	case _, ok := <-context.clientChannels[event.ChannelID].requests:
		if ok {
			t.Errorf("Channel was not closed")
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timed out waiting for channel to close")
	}
	return nil
}

type connectionCloseReplayEntry struct {
}

func (event connectionCloseReplayEntry) Execute(t *testing.T, context *clientContext) error {
	if err := context.conn.Close(); err != nil {
		if err == io.EOF {
			t.Errorf("Connection already closed")
		} else {
			return err
		}
	}
	return nil
}

func (event connectionCloseReplayEntry) Wait(t *testing.T, context *clientContext) error {
	result := make(chan error)
	go func() {
		result <- context.conn.Wait()
	}()
	select {
	case err := <-result:
		return err
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timed out waiting for connection to close")
	}
	return nil
}

type channelRequestReplayEntry struct {
	ChannelID int    `json:"channel_id"`
	Type      string `json:"type"`
	WantReply bool   `json:"want_reply"`
	Payload   string `json:"payload"`

	Accepted bool `json:"accepted"`
}

func (event channelRequestReplayEntry) Execute(t *testing.T, context *clientContext) error {
	rawPayload, err := base64.RawStdEncoding.DecodeString(event.Payload)
	if err != nil {
		return err
	}
	accepted, err := context.clientChannels[event.ChannelID].channel.SendRequest(event.Type, event.WantReply, rawPayload)
	if err != nil {
		return err
	}
	if accepted != event.Accepted {
		t.Errorf("Accepted mismatch: got %v, want %v", accepted, event.Accepted)
	}
	return nil
}

func (event channelRequestReplayEntry) Wait(t *testing.T, context *clientContext) error {
	select {
	case request, ok := <-context.clientChannels[event.ChannelID].requests:
		if !ok {
			t.Errorf("Channel was closed")
			return nil
		}
		if request.WantReply {
			if err := request.Reply(event.Accepted, nil); err != nil {
				return err
			}
		}
		if request.Type != event.Type {
			t.Errorf("Type mismatch: got %v, want %v", request.Type, event.Type)
		}
		encodedPayload := base64.RawStdEncoding.EncodeToString(request.Payload)
		if encodedPayload != event.Payload {
			t.Errorf("Payload mismatch: got %v, want %v", encodedPayload, event.Payload)
		}
		if request.WantReply != event.WantReply {
			t.Errorf("WantReply mismatch: got %v, want %v", request.WantReply, event.WantReply)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timed out waiting for request")
	}
	return nil
}

type channelErrorReplayEntry struct {
	ChannelID int    `json:"channel_id"`
	Data      string `json:"data"`
}

func (event channelErrorReplayEntry) Execute(t *testing.T, context *clientContext) error {
	return fmt.Errorf("client can't send stderr")
}

func (event channelErrorReplayEntry) Wait(t *testing.T, context *clientContext) error {
	buffer := make([]byte, len(event.Data))
	data := make(chan readWriteResult)
	go func() {
		n, err := context.clientChannels[event.ChannelID].channel.Stderr().Read(buffer)
		data <- readWriteResult{n, err}
	}()
	select {
	case result := <-data:
		if result.err != nil {
			return result.err
		}
		if result.n != len(event.Data) {
			t.Errorf("Read %d bytes, want %d", result.n, len(event.Data))
		}
		if string(buffer[:result.n]) != event.Data {
			t.Errorf("Data mismatch: got %q, want %q", string(buffer[:result.n]), event.Data)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timed out reading from channel. Data so far: %q, want %q", string(buffer), event.Data)
	}
	return nil
}

func TestReplay(t *testing.T) {
	tempDir := t.TempDir()

	keyFile, err := generateKey(tempDir, ecdsa_key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config{}
	cfg.Server.HostKeys = []string{keyFile}
	cfg.Server.TCPIPServices = map[uint32]string{
		80: "HTTP",
	}
	cfg.Auth.NoAuth = true
	if err := cfg.setupSSHConfig(); err != nil {
		t.Fatal(err)
	}

	listener, err := sshutils.Listen("localhost:0", cfg.sshConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	testFiles, err := filepath.Glob("replay_tests/*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, testFile := range testFiles {
		fileName := strings.TrimSuffix(path.Base(testFile), path.Ext(testFile))
		for _, jsonLogging := range []bool{false, true} {
			cfg.Logging.JSON = jsonLogging
			var testName string
			if !jsonLogging {
				testName = fmt.Sprint(fileName, "_plain")
			} else {
				testName = fmt.Sprint(fileName, "_json")
			}
			t.Run(testName, func(t *testing.T) {
				logBuffer := setupLogBuffer(t, cfg)
				testCaseBytes, err := os.ReadFile(testFile)
				if err != nil {
					t.Fatal(err)
				}
				var testCase replayTest
				if err := json.Unmarshal(testCaseBytes, &testCase); err != nil {
					t.Fatal(err)
				}
				serverResult := make(chan error)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						serverResult <- err
						return
					}
					handleConnection(conn, cfg)
					serverResult <- nil
				}()
				conn, err := net.Dial("tcp", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				sshConn, newChannels, requests, err := ssh.NewClientConn(conn, listener.Addr().String(), &ssh.ClientConfig{
					User:            testCase.User,
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				})
				if err != nil {
					conn.Close()
					t.Fatal(err)
				}
				defer sshConn.Close()
				context := clientContext{
					conn:           sshConn,
					requests:       requests,
					clientChannels: []clientChannel{},
				}
				for _, event := range testCase.Events {
					var err error
					if event.Source == client {
						//t.Logf("> %v %v", event.Type, event.Entry)
						err = event.Entry.Execute(t, &context)
						time.Sleep(10 * time.Millisecond)
					} else {
						//t.Logf("< %v %#v", event.Type, event.Entry)
						err = event.Entry.Wait(t, &context)
					}
					if err != nil {
						t.Fatalf("%v: %v", event, err)
					}
				}
				if err := <-serverResult; err != nil {
					t.Fatal(err)
				}
				for _, channel := range context.clientChannels {
					for request := range channel.requests {
						t.Errorf("unexpected request: %#v", request)
					}
				}
				for newChannel := range newChannels {
					t.Errorf("unexpected new channel: %#v", newChannel)
				}
				for request := range requests {
					t.Errorf("unexpected request: %#v", request)
				}
				logs := strings.TrimSpace(logBuffer.String())
				logLines := strings.Split(logs, "\n")
				if !jsonLogging {
					if len(logLines) != len(testCase.PlainLogs) {
						t.Errorf("Logs mismatch: got %d lines, want %d. Logs:\n%s", len(logLines), len(testCase.PlainLogs), logs)
					}
					for i, logLine := range logLines {
						if i >= len(testCase.PlainLogs) {
							break
						}
						expectedLogLine := strings.ReplaceAll(testCase.PlainLogs[i], "SOURCE", conn.LocalAddr().String())
						if logLine != expectedLogLine {
							t.Errorf("Log mismatch at line %d: got \n%q, want \n%q", i, logLine, expectedLogLine)
						}
					}
				} else {
					if len(logLines) != len(testCase.JSONLogs) {
						t.Errorf("Logs mismatch: got %d lines, want %d. Logs:\n%s", len(logLines), len(testCase.JSONLogs), logs)
					}
					for i, logLine := range logLines {
						if i >= len(testCase.JSONLogs) {
							break
						}
						parsedLogLine := map[string]interface{}{}
						if err := json.Unmarshal([]byte(logLine), &parsedLogLine); err != nil {
							t.Fatal(err)
						}
						expectedLogLine := testCase.JSONLogs[i]
						expectedLogLine["source"] = conn.LocalAddr().String()
						if !reflect.DeepEqual(parsedLogLine, expectedLogLine) {
							t.Errorf("Log mismatch at line %d: got \n%#v, want \n%#v", i, parsedLogLine, expectedLogLine)
						}
					}
				}
			})
		}
	}
}
