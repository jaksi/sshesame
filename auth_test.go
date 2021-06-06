package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"path"
	"reflect"
	"regexp"
	"testing"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func authenticate(cfg *config, auth []ssh.AuthMethod, t *testing.T) (bool, string, *string) {
	key := path.Join(t.TempDir(), "server.key")
	if err := generateKey(key, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg.HostKeys = []string{key}
	if err := cfg.setupSSHConfig(); err != nil {
		t.Fatalf("Failed to setup SSH config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientSuccess := make(chan bool)
	clientBanner := make(chan *string)
	go func() {
		success := true
		var banner *string
		defer func() {
			clientSuccess <- success
			clientBanner <- banner
		}()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", Auth: auth, BannerCallback: func(message string) error {
			banner = &message
			return nil
		}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
		success = true
	}()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	serverSSHConn, _, _, err := ssh.NewServerConn(serverConn, cfg.sshConfig)
	if err == nil {
		serverSSHConn.Close()
	}
	serverConn.Close()
	success := err == nil
	logs, err := io.ReadAll(&logBuffer)
	if err != nil {
		t.Fatalf("Failed to read logs: %v", err)
	}
	if <-clientSuccess != success {
		t.Fatalf("Client (%v) and server (%v) don't agree on whether the connection was successful", !success, success)
	}
	banner := <-clientBanner
	return success, string(logs), banner
}

func TestNoAuthDisabled(t *testing.T) {
	cfg := &config{}
	cfg.PasswordAuth.Enabled = true
	success, logs, _ := authenticate(cfg, nil, t)
	if success {
		t.Errorf("success=%v, want false", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
}

func TestNoAuthEnabled(t *testing.T) {
	cfg := &config{NoClientAuth: true}
	success, logs, _ := authenticate(cfg, nil, t)
	if !success {
		t.Errorf("success=%v, want true", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
}

func TestPasswordDisabled(t *testing.T) {
	cfg := &config{}
	cfg.PublicKeyAuth.Enabled = true
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.Password("hunter2")}, t)
	if success {
		t.Errorf("success=%v, want false", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
}

func TestPasswordEnabled(t *testing.T) {
	cfg := &config{}
	cfg.PasswordAuth.Enabled = true
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.Password("hunter2")}, t)
	if success {
		t.Errorf("success=%v, want false", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Password authentication attempted" client_version=SSH-2.0-Go password=hunter2 remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=password remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
}

func TestPasswordAccepted(t *testing.T) {
	cfg := &config{}
	cfg.PasswordAuth.Enabled = true
	cfg.PasswordAuth.Accepted = true
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.Password("hunter2")}, t)
	if !success {
		t.Errorf("success=%v, want true", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Password authentication attempted" client_version=SSH-2.0-Go password=hunter2 remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=password remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
}

func TestPublicKeyDisabled(t *testing.T) {
	cfg := &config{}
	cfg.PasswordAuth.Enabled = true
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("Failed to get SSH key: %v", err)
	}
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.PublicKeys(signer)}, t)
	if success {
		t.Errorf("success=%v, want false", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
}

func TestPublicKeyEnabled(t *testing.T) {
	cfg := &config{}
	cfg.PublicKeyAuth.Enabled = true
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("Failed to get SSH key: %v", err)
	}
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.PublicKeys(signer)}, t)
	if success {
		t.Errorf("success=%v, want false", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Public key authentication attempted" client_version=SSH-2.0-Go public_key_fingerprint="([^"]+)" remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=publickey remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
$`)
	matches := expectedLogs.FindStringSubmatch(logs)
	expectedMatches := []string{logs, ssh.FingerprintSHA256(signer.PublicKey())}
	if !reflect.DeepEqual(matches, expectedMatches) {
		t.Errorf("matches=%v, want %v", matches, expectedMatches)
	}
}

func TestPublicKeyAccepted(t *testing.T) {
	cfg := &config{}
	cfg.PublicKeyAuth.Enabled = true
	cfg.PublicKeyAuth.Accepted = true
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("Failed to get SSH key: %v", err)
	}
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.PublicKeys(signer)}, t)
	if !success {
		t.Errorf("success=%v, want true", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Public key authentication attempted" client_version=SSH-2.0-Go public_key_fingerprint="([^"]+)" remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=publickey remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
$`)
	matches := expectedLogs.FindStringSubmatch(logs)
	expectedMatches := []string{logs, ssh.FingerprintSHA256(signer.PublicKey())}
	if !reflect.DeepEqual(matches, expectedMatches) {
		t.Errorf("matches=%v, want %v", matches, expectedMatches)
	}
}

func TestKeyboardInteractiveDisabled(t *testing.T) {
	cfg := &config{}
	cfg.PublicKeyAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Instruction = "instruction"
	cfg.KeyboardInteractiveAuth.Questions = append(cfg.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q1", true})
	cfg.KeyboardInteractiveAuth.Questions = append(cfg.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q2", false})
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		return []string{"a1", "a2"}, nil
	})}, t)
	if success {
		t.Errorf("success=%v, want false", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
}

func TestKeyboardInteractiveEnabled(t *testing.T) {
	cfg := &config{}
	cfg.KeyboardInteractiveAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Instruction = "instruction"
	cfg.KeyboardInteractiveAuth.Questions = append(cfg.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q1", true})
	cfg.KeyboardInteractiveAuth.Questions = append(cfg.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q2", false})
	var receivedInstruction string
	var receivedQuestions []string
	var receivedEchos []bool
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		receivedInstruction = instruction
		receivedQuestions = questions
		receivedEchos = echos
		return []string{"a1", "a2"}, nil
	})}, t)
	if receivedInstruction != cfg.KeyboardInteractiveAuth.Instruction {
		t.Errorf("receivedInstruction=%v, want %v", receivedInstruction, cfg.KeyboardInteractiveAuth.Instruction)
	}
	if len(receivedQuestions) != len(cfg.KeyboardInteractiveAuth.Questions) {
		t.Errorf("len(receivedQuestions)=%v, want %v", len(receivedQuestions), len(cfg.KeyboardInteractiveAuth.Questions))
	}
	if len(receivedEchos) != len(cfg.KeyboardInteractiveAuth.Questions) {
		t.Errorf("len(receivedEchos)=%v, want %v", len(receivedEchos), len(cfg.KeyboardInteractiveAuth.Questions))
	}
	for i := range cfg.KeyboardInteractiveAuth.Questions {
		if receivedQuestions[i] != cfg.KeyboardInteractiveAuth.Questions[i].Text {
			t.Errorf("receivedQuestions[%v]=%v, want %v", i, receivedQuestions[i], cfg.KeyboardInteractiveAuth.Questions[i].Text)
		}
		if receivedEchos[i] != cfg.KeyboardInteractiveAuth.Questions[i].Echo {
			t.Errorf("receivedEchos[%v]=%v, want %v", i, receivedEchos[i], cfg.KeyboardInteractiveAuth.Questions[i].Echo)
		}
	}
	if success {
		t.Errorf("success=%v, want false", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Keyboard interactive authentication attempted" answers="a1, a2" client_version=SSH-2.0-Go remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=keyboard-interactive remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
}

func TestKeyboardInteractiveFailed(t *testing.T) {
	cfg := &config{}
	cfg.KeyboardInteractiveAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Instruction = "instruction"
	cfg.KeyboardInteractiveAuth.Questions = append(cfg.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q1", true})
	cfg.KeyboardInteractiveAuth.Questions = append(cfg.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q2", false})
	var receivedInstruction string
	var receivedQuestions []string
	var receivedEchos []bool
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		receivedInstruction = instruction
		receivedQuestions = questions
		receivedEchos = echos
		return []string{"a1"}, nil
	})}, t)
	if receivedInstruction != cfg.KeyboardInteractiveAuth.Instruction {
		t.Errorf("receivedInstruction=%v, want %v", receivedInstruction, cfg.KeyboardInteractiveAuth.Instruction)
	}
	if len(receivedQuestions) != len(cfg.KeyboardInteractiveAuth.Questions) {
		t.Errorf("len(receivedQuestions)=%v, want %v", len(receivedQuestions), len(cfg.KeyboardInteractiveAuth.Questions))
	}
	if len(receivedEchos) != len(cfg.KeyboardInteractiveAuth.Questions) {
		t.Errorf("len(receivedEchos)=%v, want %v", len(receivedEchos), len(cfg.KeyboardInteractiveAuth.Questions))
	}
	for i := range cfg.KeyboardInteractiveAuth.Questions {
		if receivedQuestions[i] != cfg.KeyboardInteractiveAuth.Questions[i].Text {
			t.Errorf("receivedQuestions[%v]=%v, want %v", i, receivedQuestions[i], cfg.KeyboardInteractiveAuth.Questions[i].Text)
		}
		if receivedEchos[i] != cfg.KeyboardInteractiveAuth.Questions[i].Echo {
			t.Errorf("receivedEchos[%v]=%v, want %v", i, receivedEchos[i], cfg.KeyboardInteractiveAuth.Questions[i].Echo)
		}
	}
	if success {
		t.Errorf("success=%v, want false", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=keyboard-interactive remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
}

func TestKeyboardInteractiveAccepted(t *testing.T) {
	cfg := &config{}
	cfg.KeyboardInteractiveAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Accepted = true
	cfg.KeyboardInteractiveAuth.Instruction = "instruction"
	cfg.KeyboardInteractiveAuth.Questions = append(cfg.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q1", true})
	cfg.KeyboardInteractiveAuth.Questions = append(cfg.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q2", false})
	var receivedInstruction string
	var receivedQuestions []string
	var receivedEchos []bool
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		receivedInstruction = instruction
		receivedQuestions = questions
		receivedEchos = echos
		return []string{"a1", "a2"}, nil
	})}, t)
	if receivedInstruction != cfg.KeyboardInteractiveAuth.Instruction {
		t.Errorf("receivedInstruction=%v, want %v", receivedInstruction, cfg.KeyboardInteractiveAuth.Instruction)
	}
	if len(receivedQuestions) != len(cfg.KeyboardInteractiveAuth.Questions) {
		t.Errorf("len(receivedQuestions)=%v, want %v", len(receivedQuestions), len(cfg.KeyboardInteractiveAuth.Questions))
	}
	if len(receivedEchos) != len(cfg.KeyboardInteractiveAuth.Questions) {
		t.Errorf("len(receivedEchos)=%v, want %v", len(receivedEchos), len(cfg.KeyboardInteractiveAuth.Questions))
	}
	for i := range cfg.KeyboardInteractiveAuth.Questions {
		if receivedQuestions[i] != cfg.KeyboardInteractiveAuth.Questions[i].Text {
			t.Errorf("receivedQuestions[%v]=%v, want %v", i, receivedQuestions[i], cfg.KeyboardInteractiveAuth.Questions[i].Text)
		}
		if receivedEchos[i] != cfg.KeyboardInteractiveAuth.Questions[i].Echo {
			t.Errorf("receivedEchos[%v]=%v, want %v", i, receivedEchos[i], cfg.KeyboardInteractiveAuth.Questions[i].Echo)
		}
	}
	if success {
		t.Errorf("success=%v, want false", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Keyboard interactive authentication attempted" answers="a1, a2" client_version=SSH-2.0-Go remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=keyboard-interactive remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
}

func TestAllEnabled(t *testing.T) {
	cfg := &config{}
	cfg.PasswordAuth.Enabled = true
	cfg.PublicKeyAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Instruction = "instruction"
	cfg.KeyboardInteractiveAuth.Questions = append(cfg.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q1", true})
	cfg.KeyboardInteractiveAuth.Questions = append(cfg.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q2", false})
	var receivedInstruction string
	var receivedQuestions []string
	var receivedEchos []bool
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("Failed to get SSH key: %v", err)
	}
	success, logs, _ := authenticate(cfg, []ssh.AuthMethod{ssh.Password("hunter2"), ssh.PublicKeys(signer), ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		receivedInstruction = instruction
		receivedQuestions = questions
		receivedEchos = echos
		return []string{"a1", "a2"}, nil
	})}, t)
	if receivedInstruction != cfg.KeyboardInteractiveAuth.Instruction {
		t.Errorf("receivedInstruction=%v, want %v", receivedInstruction, cfg.KeyboardInteractiveAuth.Instruction)
	}
	if len(receivedQuestions) != len(cfg.KeyboardInteractiveAuth.Questions) {
		t.Errorf("len(receivedQuestions)=%v, want %v", len(receivedQuestions), len(cfg.KeyboardInteractiveAuth.Questions))
	}
	if len(receivedEchos) != len(cfg.KeyboardInteractiveAuth.Questions) {
		t.Errorf("len(receivedEchos)=%v, want %v", len(receivedEchos), len(cfg.KeyboardInteractiveAuth.Questions))
	}
	for i := range cfg.KeyboardInteractiveAuth.Questions {
		if receivedQuestions[i] != cfg.KeyboardInteractiveAuth.Questions[i].Text {
			t.Errorf("receivedQuestions[%v]=%v, want %v", i, receivedQuestions[i], cfg.KeyboardInteractiveAuth.Questions[i].Text)
		}
		if receivedEchos[i] != cfg.KeyboardInteractiveAuth.Questions[i].Echo {
			t.Errorf("receivedEchos[%v]=%v, want %v", i, receivedEchos[i], cfg.KeyboardInteractiveAuth.Questions[i].Echo)
		}
	}
	if success {
		t.Errorf("success=%v, want false", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Password authentication attempted" client_version=SSH-2.0-Go password=hunter2 remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=password remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Public key authentication attempted" client_version=SSH-2.0-Go public_key_fingerprint="([^"]+)" remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=publickey remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Keyboard interactive authentication attempted" answers="a1, a2" client_version=SSH-2.0-Go remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=keyboard-interactive remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
$`)
	matches := expectedLogs.FindStringSubmatch(logs)
	expectedMatches := []string{logs, ssh.FingerprintSHA256(signer.PublicKey())}
	if !reflect.DeepEqual(matches, expectedMatches) {
		t.Errorf("matches=%v, want %v", matches, expectedMatches)
	}
}

func TestNoBanner(t *testing.T) {
	cfg := &config{NoClientAuth: true}
	success, logs, banner := authenticate(cfg, nil, t)
	if !success {
		t.Errorf("success=%v, want true", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
	if banner != nil {
		t.Errorf("banner=%v, want nil", banner)
	}
}

func TestBanner(t *testing.T) {
	cfg := &config{NoClientAuth: true, Banner: "Lorem\nipsum\rdolor\r\nsit\n\namet"}
	success, logs, banner := authenticate(cfg, nil, t)
	if !success {
		t.Errorf("success=%v, want true", success)
	}
	expectedLogs := regexp.MustCompile(`^level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_address="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", string(logs), expectedLogs)
	}
	expectedBanner := "Lorem\r\nipsum\rdolor\r\nsit\r\n\r\namet\r\n"
	if banner == nil {
		t.Errorf("banner=nil, want %v", expectedBanner)
	} else if *banner != expectedBanner {
		t.Errorf("*banner=%v, want %v", *banner, expectedBanner)
	}
}
