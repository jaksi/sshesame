package main

import (
	"bytes"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
)

type mockConnMetadata struct{}

func (metadata *mockConnMetadata) User() string {
	return "root"
}

func (metadata *mockConnMetadata) SessionID() []byte {
	return []byte("somesession")
}

func (metadata *mockConnMetadata) ClientVersion() []byte {
	return []byte("SSH-2.0-testclient")
}

func (metadata *mockConnMetadata) ServerVersion() []byte {
	return []byte("SSH-2.0-testserver")
}

func (metadata *mockConnMetadata) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func (metadata *mockConnMetadata) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2022}
}

func setupLogBuffer() *bytes.Buffer {
	buffer := &bytes.Buffer{}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	logrus.SetOutput(buffer)
	return buffer
}

func TestAuthLogCallbackSuccess(t *testing.T) {
	logBuffer := setupLogBuffer()
	authLogCallback(&mockConnMetadata{}, "some-method", nil)
	logs := logBuffer.String()
	expectedLogs := `level=info msg="Client attempted to authenticate" client_version=SSH-2.0-testclient method=some-method remote_address="127.0.0.1:1234" session_id=c29tZXNlc3Npb24 success=true user=root
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestAuthLogCallbackFail(t *testing.T) {
	logBuffer := setupLogBuffer()
	authLogCallback(&mockConnMetadata{}, "some-other-method", errors.New(""))
	logs := logBuffer.String()
	expectedLogs := `level=info msg="Client attempted to authenticate" client_version=SSH-2.0-testclient method=some-other-method remote_address="127.0.0.1:1234" session_id=c29tZXNlc3Npb24 success=false user=root
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPasswordCallbackDisabled(t *testing.T) {
	cfg := &config{}
	cfg.PasswordAuth.Enabled = false
	callback := cfg.getPasswordCallback()
	if callback != nil {
		t.Errorf("callback=%p, want nil", callback)
	}
}

func TestPasswordCallbackFail(t *testing.T) {
	cfg := &config{}
	cfg.PasswordAuth.Enabled = true
	cfg.PasswordAuth.Accepted = false
	callback := cfg.getPasswordCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer()
	permissions, err := callback(&mockConnMetadata{}, []byte("hunter2"))
	logs := logBuffer.String()
	if err == nil {
		t.Errorf("err=nil, want an error")
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `level=info msg="Password authentication attempted" client_version=SSH-2.0-testclient password=hunter2 remote_address="127.0.0.1:1234" session_id=c29tZXNlc3Npb24 success=false user=root
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPasswordCallbackSuccess(t *testing.T) {
	cfg := &config{}
	cfg.PasswordAuth.Enabled = true
	cfg.PasswordAuth.Accepted = true
	callback := cfg.getPasswordCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer()
	permissions, err := callback(&mockConnMetadata{}, []byte("hunter2"))
	logs := logBuffer.String()
	if err != nil {
		t.Errorf("err=%v, want nil", err)
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `level=info msg="Password authentication attempted" client_version=SSH-2.0-testclient password=hunter2 remote_address="127.0.0.1:1234" session_id=c29tZXNlc3Npb24 success=true user=root
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPublicKeyCallbackDisabled(t *testing.T) {
	cfg := &config{}
	cfg.PublicKeyAuth.Enabled = false
	callback := cfg.getPublicKeyCallback()
	if callback != nil {
		t.Errorf("callback=%p, want nil", callback)
	}
}

func TestPublicKeyCallbackFail(t *testing.T) {
	cfg := &config{}
	cfg.PublicKeyAuth.Enabled = true
	cfg.PublicKeyAuth.Accepted = false
	callback := cfg.getPublicKeyCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer()
	permissions, err := callback(&mockConnMetadata{}, &mockPublicKey{})
	logs := logBuffer.String()
	if err == nil {
		t.Errorf("err=nil, want an error")
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `level=info msg="Public key authentication attempted" client_version=SSH-2.0-testclient public_key_fingerprint="SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" remote_address="127.0.0.1:1234" session_id=c29tZXNlc3Npb24 success=false user=root
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPublicKeyCallbackSuccess(t *testing.T) {
	cfg := &config{}
	cfg.PublicKeyAuth.Enabled = true
	cfg.PublicKeyAuth.Accepted = true
	callback := cfg.getPublicKeyCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer()
	permissions, err := callback(&mockConnMetadata{}, &mockPublicKey{})
	logs := logBuffer.String()
	if err != nil {
		t.Errorf("err=%v, want nil", err)
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `level=info msg="Public key authentication attempted" client_version=SSH-2.0-testclient public_key_fingerprint="SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" remote_address="127.0.0.1:1234" session_id=c29tZXNlc3Npb24 success=true user=root
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestKeyboardInteractiveCallbackDisabled(t *testing.T) {
	cfg := &config{}
	cfg.KeyboardInteractiveAuth.Enabled = false
	cfg.KeyboardInteractiveAuth.Instruction = "inst"
	cfg.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	callback := cfg.getKeyboardInteractiveCallback()
	if callback != nil {
		t.Errorf("callback=%p, want nil", callback)
	}
}

func TestKeyboardInteractiveCallbackError(t *testing.T) {
	cfg := &config{}
	cfg.KeyboardInteractiveAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Accepted = false
	cfg.KeyboardInteractiveAuth.Instruction = "inst"
	cfg.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	callback := cfg.getKeyboardInteractiveCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer()
	permissions, err := callback(&mockConnMetadata{}, func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		if user != "root" {
			t.Errorf("user=%v, want root", user)
		}
		if instruction != "inst" {
			t.Errorf("instruction=%v, want inst", instruction)
		}
		if !reflect.DeepEqual(questions, []string{"q1", "q2"}) {
			t.Errorf("questions=%v, want [q1, q2]", questions)
		}
		if !reflect.DeepEqual(echos, []bool{true, false}) {
			t.Errorf("echos=%v, want [true, false]", echos)
		}
		return nil, errors.New("")
	})
	logs := logBuffer.String()
	if err == nil {
		t.Errorf("err=nil, want an error")
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := ``
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestKeyboardInteractiveCallbackFail(t *testing.T) {
	cfg := &config{}
	cfg.KeyboardInteractiveAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Accepted = false
	cfg.KeyboardInteractiveAuth.Instruction = "inst"
	cfg.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	callback := cfg.getKeyboardInteractiveCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer()
	permissions, err := callback(&mockConnMetadata{}, func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		return []string{"a1", "a2"}, nil
	})
	logs := logBuffer.String()
	if err == nil {
		t.Errorf("err=nil, want an error")
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `level=info msg="Keyboard interactive authentication attempted" answers="a1, a2" client_version=SSH-2.0-testclient remote_address="127.0.0.1:1234" session_id=c29tZXNlc3Npb24 success=false user=root
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestKeyboardInteractiveCallbackSuccess(t *testing.T) {
	cfg := &config{}
	cfg.KeyboardInteractiveAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Accepted = true
	cfg.KeyboardInteractiveAuth.Instruction = "inst"
	cfg.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	callback := cfg.getKeyboardInteractiveCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer()
	permissions, err := callback(&mockConnMetadata{}, func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		return []string{"a1", "a2"}, nil
	})
	logs := logBuffer.String()
	if err != nil {
		t.Errorf("err=%v, want nil", err)
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `level=info msg="Keyboard interactive authentication attempted" answers="a1, a2" client_version=SSH-2.0-testclient remote_address="127.0.0.1:1234" session_id=c29tZXNlc3Npb24 success=true user=root
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestBannerCallbackDisabled(t *testing.T) {
	cfg := &config{Banner: ""}
	callback := cfg.getBannerCallback()
	if callback != nil {
		t.Errorf("callback=%p, want nil", callback)
	}
}

func TestBannerCallback(t *testing.T) {
	cfg := &config{Banner: "Lorem\nIpsum\r\nDolor\n\nSit Amet"}
	callback := cfg.getBannerCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	banner := callback(&mockConnMetadata{})
	expectedBanner := "Lorem\r\nIpsum\r\nDolor\r\n\r\nSit Amet\r\n"
	if banner != expectedBanner {
		t.Errorf("banner=%v, want %v", banner, expectedBanner)
	}
}
