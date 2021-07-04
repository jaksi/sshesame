package main

import (
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

type mockRequest struct {
	_name        string
	_wantReply   bool
	_payload     []byte
	replyCount   int
	replyOK      bool
	replyPayload []byte
}

func (req *mockRequest) name() string {
	return req._name
}

func (req *mockRequest) wantReply() bool {
	return req._wantReply
}

func (req *mockRequest) payload() []byte {
	return req._payload
}

func (req *mockRequest) reply(ok bool, payload []byte) error {
	req.replyCount++
	req.replyOK = ok
	req.replyPayload = payload
	return nil
}

func (req *mockRequest) test(t *testing.T, expectedError bool, expectedReply bool, expectedOK bool) (string, []byte) {
	cfg := &config{}
	logBuffer := setupLogBuffer(cfg)
	err := handleGlobalRequest(req, connMetadata{mockConnMetadata{}, cfg})
	if expectedError {
		if err == nil {
			t.Errorf("err=nil, want an error")
		}
	} else {
		if err != nil {
			t.Fatalf("Failed to handle global request: %v", err)
		}
	}
	var expectedReplyCount int
	if expectedReply {
		expectedReplyCount = 1
	} else {
		expectedReplyCount = 0
	}
	if req.replyCount != expectedReplyCount {
		t.Errorf("req.replyCount=%v, want %v", req.replyCount, expectedReplyCount)
	}
	if req.replyOK != expectedOK {
		t.Errorf("req.replyOK=%v, want %v", req.replyOK, expectedOK)
	}
	return logBuffer.String(), req.replyPayload
}

func TestUnsupportedRequest(t *testing.T) {
	req := &mockRequest{_name: "nope"}
	logs, _ := req.test(t, false, false, false)
	expectedLogs := ``
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestUnsupportedRequestWantReply(t *testing.T) {
	req := &mockRequest{_name: "nope", _wantReply: true}
	logs, payload := req.test(t, false, true, false)
	if payload != nil {
		t.Errorf("payload=%v, want nil", payload)
	}
	expectedLogs := ``
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestTCPIPForwardFail(t *testing.T) {
	req := &mockRequest{_name: "tcpip-forward"}
	logs, _ := req.test(t, true, false, false)
	expectedLogs := ``
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestTCPIPForward(t *testing.T) {
	req := &mockRequest{_name: "tcpip-forward", _payload: ssh.Marshal(struct {
		string
		uint32
	}{"localhost", 1234})}
	logs, _ := req.test(t, false, false, false)
	expectedLogs := `[127.0.0.1:1234] TCP/IP forwarding on localhost:1234 requested
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestTCPIPForwardWantReply(t *testing.T) {
	req := &mockRequest{_name: "tcpip-forward", _wantReply: true, _payload: ssh.Marshal(struct {
		string
		uint32
	}{"localhost", 1234})}
	logs, payload := req.test(t, false, true, true)
	if payload != nil {
		t.Errorf("payload=%v, want nil", payload)
	}
	expectedLogs := `[127.0.0.1:1234] TCP/IP forwarding on localhost:1234 requested
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestTCPIPForwardAllocatePort(t *testing.T) {
	req := &mockRequest{_name: "tcpip-forward", _payload: ssh.Marshal(struct {
		string
		uint32
	}{"localhost", 0})}
	logs, _ := req.test(t, false, false, false)
	expectedLogs := `[127.0.0.1:1234] TCP/IP forwarding on localhost:0 requested
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestTCPIPForwardAllocatePortWantReply(t *testing.T) {
	req := &mockRequest{_name: "tcpip-forward", _wantReply: true, _payload: ssh.Marshal(struct {
		string
		uint32
	}{"localhost", 0})}
	logs, payload := req.test(t, false, true, true)
	parsedPayload := struct{ Port uint32 }{}
	if err := ssh.Unmarshal(payload, &parsedPayload); err != nil {
		t.Fatalf("Failed to parse response payload: %v", err)
	}
	if parsedPayload.Port < 1024 || parsedPayload.Port > 65535 {
		t.Errorf("parsedPayload.Port=%v, want 1024>=x>=65535", parsedPayload.Port)
	}
	expectedLogs := `[127.0.0.1:1234] TCP/IP forwarding on localhost:0 requested
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestCancelTCPIPForwardFail(t *testing.T) {
	req := &mockRequest{_name: "cancel-tcpip-forward"}
	logs, _ := req.test(t, true, false, false)
	expectedLogs := ``
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestCancelTCPIPForward(t *testing.T) {
	req := &mockRequest{_name: "cancel-tcpip-forward", _payload: ssh.Marshal(struct {
		string
		uint32
	}{"localhost", 0})}
	logs, _ := req.test(t, false, false, false)
	expectedLogs := `[127.0.0.1:1234] TCP/IP forwarding on localhost:0 canceled
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestCancelTCPIPForwardWantReply(t *testing.T) {
	req := &mockRequest{_name: "cancel-tcpip-forward", _wantReply: true, _payload: ssh.Marshal(struct {
		string
		uint32
	}{"localhost", 0})}
	logs, payload := req.test(t, false, true, true)
	if payload != nil {
		t.Errorf("payload=%v, want nil", payload)
	}
	expectedLogs := `[127.0.0.1:1234] TCP/IP forwarding on localhost:0 canceled
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestCreateHostKeysRequestPayload(t *testing.T) {
	payload := createHostkeysRequestPayload([]ssh.Signer{mockSigner{rsa_key}, mockSigner{ecdsa_key}})
	expectedPayload := []byte("\x00\x00\x00\x03rsa\x00\x00\x00\x05ecdsa")
	if !reflect.DeepEqual(payload, expectedPayload) {
		t.Errorf("payload=%v, want %v", payload, expectedPayload)
	}
}
