package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"path"
	"regexp"
	"testing"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func TestNoAuthDisabled(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}}
	cfg.PasswordAuth.Enabled = true
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test"})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestNoAuthEnabled(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}, NoClientAuth: true}
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test"})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="SSH connection established" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="SSH connection closed" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestPasswordDisabled(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}}
	cfg.PublicKeyAuth.Enabled = true
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", Auth: []ssh.AuthMethod{ssh.Password("hunter2")}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestPasswordEnabled(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}}
	cfg.PasswordAuth.Enabled = true
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", Auth: []ssh.AuthMethod{ssh.Password("hunter2")}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Password authentication attempted" client_version=SSH-2.0-Go password=hunter2 remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=password remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestPasswordAccepted(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}}
	cfg.PasswordAuth.Enabled = true
	cfg.PasswordAuth.Accepted = true
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", Auth: []ssh.AuthMethod{ssh.Password("hunter2")}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Password authentication attempted" client_version=SSH-2.0-Go password=hunter2 remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=password remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="SSH connection established" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="SSH connection closed" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestPublicKeyDisabled(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}}
	cfg.PasswordAuth.Enabled = true
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	keyBytes, err := ioutil.ReadFile(hostKeyFileName)
	if err != nil {
		t.Fatalf("Failed to read host key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse host key: %v", err)
	}
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestPublicKeyEnabled(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}}
	cfg.PublicKeyAuth.Enabled = true
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	keyBytes, err := ioutil.ReadFile(hostKeyFileName)
	if err != nil {
		t.Fatalf("Failed to read host key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse host key: %v", err)
	}
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Public key authentication attempted" client_version=SSH-2.0-Go public_key_fingerprint="SHA256:[^"]+" remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=publickey remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestPublicKeyAccepted(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}}
	cfg.PublicKeyAuth.Enabled = true
	cfg.PublicKeyAuth.Accepted = true
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	keyBytes, err := ioutil.ReadFile(hostKeyFileName)
	if err != nil {
		t.Fatalf("Failed to read host key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse host key: %v", err)
	}
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Public key authentication attempted" client_version=SSH-2.0-Go public_key_fingerprint="SHA256:[^"]+" remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=publickey remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="SSH connection established" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="SSH connection closed" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestKeyboardInteractiveDisabled(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}}
	cfg.PasswordAuth.Enabled = true
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
			return []string{"answer1", "answer2"}, nil
		})}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestKeyboardInteractiveEnabled(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}}
	cfg.KeyboardInteractiveAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Instruction = "instruction"
	cfg.KeyboardInteractiveAuth.Questions = make([]struct {
		Text string
		Echo bool
	}, 2)
	cfg.KeyboardInteractiveAuth.Questions[0].Text = "question1"
	cfg.KeyboardInteractiveAuth.Questions[0].Echo = true
	cfg.KeyboardInteractiveAuth.Questions[1].Text = "question2"
	cfg.KeyboardInteractiveAuth.Questions[1].Echo = false
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
			return []string{"answer1", "answer2"}, nil
		})}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Keyboard interactive authentication attempted" answers="answer1, answer2" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=keyboard-interactive remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestKeyboardInteractiveAccepted(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}}
	cfg.KeyboardInteractiveAuth.Enabled = true
	cfg.KeyboardInteractiveAuth.Accepted = true
	cfg.KeyboardInteractiveAuth.Instruction = "instruction"
	cfg.KeyboardInteractiveAuth.Questions = make([]struct {
		Text string
		Echo bool
	}, 2)
	cfg.KeyboardInteractiveAuth.Questions[0].Text = "question1"
	cfg.KeyboardInteractiveAuth.Questions[0].Echo = true
	cfg.KeyboardInteractiveAuth.Questions[1].Text = "question2"
	cfg.KeyboardInteractiveAuth.Questions[1].Echo = false
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan interface{})
	go func() {
		defer func() { clientChan <- nil }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
			return []string{"answer1", "answer2"}, nil
		})}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		defer clientConn.Close()
	}()
	defer func() { <-clientChan }()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=false user=test
level=info msg="Keyboard interactive authentication attempted" answers="answer1, answer2" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=keyboard-interactive remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="SSH connection established" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="SSH connection closed" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestBannerDisabled(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}, NoClientAuth: true}
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan bool)
	go func() {
		bannerReceived := false
		defer func() { clientChan <- bannerReceived }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", BannerCallback: func(message string) error {
			bannerReceived = true
			return nil
		}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		t.Log(bannerReceived)
		defer clientConn.Close()
	}()
	defer func() {
		if <-clientChan {
			t.Fatalf("Client received a banner, should not have")
		}
	}()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="SSH connection established" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="SSH connection closed" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}

func TestBannerEnabled(t *testing.T) {
	hostKeyFileName := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(hostKeyFileName, rsa_key); err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := config{HostKeys: []string{hostKeyFileName}, NoClientAuth: true, Banner: "yo"}
	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	listener, err := net.Listen("tcp", "127.0.0.1:2022")
	if err != nil {
		t.Fatalf("Failet to listen: %v", err)
	}
	defer listener.Close()
	clientChan := make(chan bool)
	go func() {
		bannerReceived := false
		defer func() { clientChan <- bannerReceived }()
		clientConn, err := ssh.Dial("tcp", "127.0.0.1:2022", &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), User: "test", BannerCallback: func(message string) error {
			bannerReceived = true
			return nil
		}})
		if err != nil {
			t.Logf("Failed to connect: %v", err)
			return
		}
		t.Log(bannerReceived)
		defer clientConn.Close()
	}()
	defer func() {
		if !<-clientChan {
			t.Fatalf("Client received a banner, should not have")
		}
	}()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	handleConnection(serverConn, sshServerConfig)
	logs, err := io.ReadAll(&logBuffer)
	expectedLogs := regexp.MustCompile(`^level=info msg="Connection accepted" remote_address="127.0.0.1:\d+"
level=info msg="Client attempted to authenticate" client_version=SSH-2.0-Go method=none remote_addr="127.0.0.1:\d+" session_id=[^ ]+ success=true user=test
level=info msg="SSH connection established" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="SSH connection closed" client_version=SSH-2.0-Go remote_addr="127.0.0.1:\d+" session_id=[^ ]+ user=test
level=info msg="Connection closed" remote_address="127.0.0.1:\d+"
$`)
	if err != nil || !expectedLogs.Match(logs) {
		t.Fatalf("io.ReadAll(&logBuffer) = %v, %v, want match %v, nil", string(logs), err, expectedLogs)
	}
}
