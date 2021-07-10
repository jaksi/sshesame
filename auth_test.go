package main

import (
	"errors"
	"net"
	"reflect"
	"testing"
)

type mockConnContext struct{}

func (context mockConnContext) User() string {
	return "root"
}

func (context mockConnContext) SessionID() []byte {
	return []byte("somesession")
}

func (context mockConnContext) ClientVersion() []byte {
	return []byte("SSH-2.0-testclient")
}

func (context mockConnContext) ServerVersion() []byte {
	return []byte("SSH-2.0-testserver")
}

func (context mockConnContext) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func (context mockConnContext) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2022}
}

func TestAuthLogUninteresting(t *testing.T) {
	cfg := &config{}
	cfg.Auth.NoAuth = false
	callback := cfg.getAuthLogCallback()
	logBuffer := setupLogBuffer(t, cfg)
	callback(mockConnContext{}, "password", nil)
	logs := logBuffer.String()
	expectedLogs := ``
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestNoAuthFail(t *testing.T) {
	cfg := &config{}
	cfg.Auth.NoAuth = false
	callback := cfg.getAuthLogCallback()
	logBuffer := setupLogBuffer(t, cfg)
	callback(mockConnContext{}, "none", errors.New(""))
	logs := logBuffer.String()
	expectedLogs := `[127.0.0.1:1234] authentication for user "root" without credentials rejected
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestNoAuthSuccess(t *testing.T) {
	cfg := &config{}
	cfg.Auth.NoAuth = false
	callback := cfg.getAuthLogCallback()
	logBuffer := setupLogBuffer(t, cfg)
	callback(mockConnContext{}, "none", nil)
	logs := logBuffer.String()
	expectedLogs := `[127.0.0.1:1234] authentication for user "root" without credentials accepted
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPasswordDisabled(t *testing.T) {
	cfg := &config{}
	cfg.Auth.PasswordAuth.Enabled = false
	callback := cfg.getPasswordCallback()
	if callback != nil {
		t.Errorf("callback=%p, want nil", callback)
	}
}

func TestPasswordFail(t *testing.T) {
	cfg := &config{}
	cfg.Auth.PasswordAuth.Enabled = true
	cfg.Auth.PasswordAuth.Accepted = false
	callback := cfg.getPasswordCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, []byte("hunter2"))
	logs := logBuffer.String()
	if err == nil {
		t.Errorf("err=nil, want an error")
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `[127.0.0.1:1234] authentication for user "root" with password "hunter2" rejected
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPasswordSuccess(t *testing.T) {
	cfg := &config{}
	cfg.Auth.PasswordAuth.Enabled = true
	cfg.Auth.PasswordAuth.Accepted = true
	callback := cfg.getPasswordCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, []byte("hunter2"))
	logs := logBuffer.String()
	if err != nil {
		t.Errorf("err=%v, want nil", err)
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `[127.0.0.1:1234] authentication for user "root" with password "hunter2" accepted
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPasswordFailJSON(t *testing.T) {
	cfg := &config{}
	cfg.Logging.JSON = true
	cfg.Auth.PasswordAuth.Enabled = true
	cfg.Auth.PasswordAuth.Accepted = false
	callback := cfg.getPasswordCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, []byte("hunter2"))
	logs := logBuffer.String()
	if err == nil {
		t.Errorf("err=nil, want an error")
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `{"source":"127.0.0.1:1234","event_type":"password_auth","event":{"user":"root","accepted":false,"password":"hunter2"}}
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPasswordSuccessJSON(t *testing.T) {
	cfg := &config{}
	cfg.Logging.JSON = true
	cfg.Auth.PasswordAuth.Enabled = true
	cfg.Auth.PasswordAuth.Accepted = true
	callback := cfg.getPasswordCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, []byte("hunter2"))
	logs := logBuffer.String()
	if err != nil {
		t.Errorf("err=%v, want nil", err)
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `{"source":"127.0.0.1:1234","event_type":"password_auth","event":{"user":"root","accepted":true,"password":"hunter2"}}
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPublicKeyDisabled(t *testing.T) {
	cfg := &config{}
	cfg.Auth.PublicKeyAuth.Enabled = false
	callback := cfg.getPublicKeyCallback()
	if callback != nil {
		t.Errorf("callback=%p, want nil", callback)
	}
}

func TestPublicKeyFail(t *testing.T) {
	cfg := &config{}
	cfg.Auth.PublicKeyAuth.Enabled = true
	cfg.Auth.PublicKeyAuth.Accepted = false
	callback := cfg.getPublicKeyCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, mockPublicKey{})
	logs := logBuffer.String()
	if err == nil {
		t.Errorf("err=nil, want an error")
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `[127.0.0.1:1234] authentication for user "root" with public key "SHA256:9faRaLujz6HiqA3/g5tI2zbfNvqHbBzZ19UI86swh0Q" rejected
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPublicKeySuccess(t *testing.T) {
	cfg := &config{}
	cfg.Auth.PublicKeyAuth.Enabled = true
	cfg.Auth.PublicKeyAuth.Accepted = true
	callback := cfg.getPublicKeyCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, mockPublicKey{})
	logs := logBuffer.String()
	if err != nil {
		t.Errorf("err=%v, want nil", err)
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `[127.0.0.1:1234] authentication for user "root" with public key "SHA256:9faRaLujz6HiqA3/g5tI2zbfNvqHbBzZ19UI86swh0Q" accepted
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPublicKeyFailJSON(t *testing.T) {
	cfg := &config{}
	cfg.Logging.JSON = true
	cfg.Auth.PublicKeyAuth.Enabled = true
	cfg.Auth.PublicKeyAuth.Accepted = false
	callback := cfg.getPublicKeyCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, mockPublicKey{})
	logs := logBuffer.String()
	if err == nil {
		t.Errorf("err=nil, want an error")
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `{"source":"127.0.0.1:1234","event_type":"public_key_auth","event":{"user":"root","accepted":false,"public_key":"SHA256:9faRaLujz6HiqA3/g5tI2zbfNvqHbBzZ19UI86swh0Q"}}
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestPublicKeySuccessJSON(t *testing.T) {
	cfg := &config{}
	cfg.Logging.JSON = true
	cfg.Auth.PublicKeyAuth.Enabled = true
	cfg.Auth.PublicKeyAuth.Accepted = true
	callback := cfg.getPublicKeyCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, mockPublicKey{})
	logs := logBuffer.String()
	if err != nil {
		t.Errorf("err=%v, want nil", err)
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `{"source":"127.0.0.1:1234","event_type":"public_key_auth","event":{"user":"root","accepted":true,"public_key":"SHA256:9faRaLujz6HiqA3/g5tI2zbfNvqHbBzZ19UI86swh0Q"}}
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestKeyboardInteractiveDisabled(t *testing.T) {
	cfg := &config{}
	cfg.Auth.KeyboardInteractiveAuth.Enabled = false
	cfg.Auth.KeyboardInteractiveAuth.Instruction = "inst"
	cfg.Auth.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	callback := cfg.getKeyboardInteractiveCallback()
	if callback != nil {
		t.Errorf("callback=%p, want nil", callback)
	}
}

func TestKeyboardInteractiveError(t *testing.T) {
	cfg := &config{}
	cfg.Auth.KeyboardInteractiveAuth.Enabled = true
	cfg.Auth.KeyboardInteractiveAuth.Accepted = false
	cfg.Auth.KeyboardInteractiveAuth.Instruction = "inst"
	cfg.Auth.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	callback := cfg.getKeyboardInteractiveCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
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

func TestKeyboardInteractiveFail(t *testing.T) {
	cfg := &config{}
	cfg.Auth.KeyboardInteractiveAuth.Enabled = true
	cfg.Auth.KeyboardInteractiveAuth.Accepted = false
	cfg.Auth.KeyboardInteractiveAuth.Instruction = "inst"
	cfg.Auth.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	callback := cfg.getKeyboardInteractiveCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		return []string{"a1", "a2"}, nil
	})
	logs := logBuffer.String()
	if err == nil {
		t.Errorf("err=nil, want an error")
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `[127.0.0.1:1234] authentication for user "root" with keyboard interactive answers ["a1" "a2"] rejected
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestKeyboardInteractiveSuccess(t *testing.T) {
	cfg := &config{}
	cfg.Auth.KeyboardInteractiveAuth.Enabled = true
	cfg.Auth.KeyboardInteractiveAuth.Accepted = true
	cfg.Auth.KeyboardInteractiveAuth.Instruction = "inst"
	cfg.Auth.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	callback := cfg.getKeyboardInteractiveCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		return []string{"a1", "a2"}, nil
	})
	logs := logBuffer.String()
	if err != nil {
		t.Errorf("err=%v, want nil", err)
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `[127.0.0.1:1234] authentication for user "root" with keyboard interactive answers ["a1" "a2"] accepted
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestKeyboardInteractiveFailJSON(t *testing.T) {
	cfg := &config{}
	cfg.Logging.JSON = true
	cfg.Auth.KeyboardInteractiveAuth.Enabled = true
	cfg.Auth.KeyboardInteractiveAuth.Accepted = false
	cfg.Auth.KeyboardInteractiveAuth.Instruction = "inst"
	cfg.Auth.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	callback := cfg.getKeyboardInteractiveCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		return []string{"a1", "a2"}, nil
	})
	logs := logBuffer.String()
	if err == nil {
		t.Errorf("err=nil, want an error")
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `{"source":"127.0.0.1:1234","event_type":"keyboard_interactive_auth","event":{"user":"root","accepted":false,"answers":["a1","a2"]}}
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestKeyboardInteractiveSuccessJSON(t *testing.T) {
	cfg := &config{}
	cfg.Logging.JSON = true
	cfg.Auth.KeyboardInteractiveAuth.Enabled = true
	cfg.Auth.KeyboardInteractiveAuth.Accepted = true
	cfg.Auth.KeyboardInteractiveAuth.Instruction = "inst"
	cfg.Auth.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	callback := cfg.getKeyboardInteractiveCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	logBuffer := setupLogBuffer(t, cfg)
	permissions, err := callback(mockConnContext{}, func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		return []string{"a1", "a2"}, nil
	})
	logs := logBuffer.String()
	if err != nil {
		t.Errorf("err=%v, want nil", err)
	}
	if permissions != nil {
		t.Errorf("permissions=%v, want nil", permissions)
	}
	expectedLogs := `{"source":"127.0.0.1:1234","event_type":"keyboard_interactive_auth","event":{"user":"root","accepted":true,"answers":["a1","a2"]}}
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", string(logs), expectedLogs)
	}
}

func TestBannerDisabled(t *testing.T) {
	cfg := &config{}
	cfg.SSHProto.Banner = ""
	callback := cfg.getBannerCallback()
	if callback != nil {
		t.Errorf("callback=%p, want nil", callback)
	}
}

func TestBanner(t *testing.T) {
	cfg := &config{}
	cfg.SSHProto.Banner = "Lorem\nIpsum\r\nDolor\n\nSit Amet"
	callback := cfg.getBannerCallback()
	if callback == nil {
		t.Fatalf("callback=nil, want a function")
	}
	banner := callback(mockConnContext{})
	expectedBanner := "Lorem\r\nIpsum\r\nDolor\r\n\r\nSit Amet\r\n"
	if banner != expectedBanner {
		t.Errorf("banner=%v, want %v", banner, expectedBanner)
	}
}
