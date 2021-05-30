package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func TestDefaultConfig(t *testing.T) {
	dataDir := t.TempDir()
	cfg, err := getConfig("", dataDir)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := config{
		ListenAddress: "127.0.0.1:2022",
		HostKeys: []string{
			path.Join(dataDir, "host_rsa_key"),
			path.Join(dataDir, "host_ecdsa_key"),
			path.Join(dataDir, "host_ed25519_key"),
		},
		ServerVersion: "SSH-2.0-sshesame",
		Banner:        "This is an SSH honeypot. Everything is logged and monitored.\r\n",
	}
	expectedConfig.PasswordAuth.Enabled = true
	expectedConfig.PasswordAuth.Accepted = true
	expectedConfig.PublicKeyAuth.Enabled = true
	if !reflect.DeepEqual(*cfg, expectedConfig) {
		t.Fatalf("Default getConfig() = %+v, want %+v", *cfg, expectedConfig)
	}
	for _, hostKeyFileName := range cfg.HostKeys {
		hostKeyBytes, err := ioutil.ReadFile(hostKeyFileName)
		if err != nil {
			t.Fatalf("Failed to read host key %v: %v", hostKeyFileName, err)
		}
		signer, err := ssh.ParsePrivateKey(hostKeyBytes)
		if err != nil {
			t.Fatalf("Failed to parse host key %v: %v", hostKeyFileName, err)
		}
		expectedKeyType, ok := map[string]string{"host_rsa_key": "ssh-rsa", "host_ecdsa_key": "ecdsa-sha2-nistp256", "host_ed25519_key": "ssh-ed25519"}[path.Base(hostKeyFileName)]
		if !ok {
			t.Fatalf("Unexpected key file name %v", hostKeyFileName)
		}
		if signer.PublicKey().Type() != expectedKeyType {
			t.Fatalf("host key type = %v, want %v", signer.PublicKey().Type(), expectedKeyType)
		}
	}

	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	if sshServerConfig.AuthLogCallback == nil {
		t.Fatalf("sshServerConfig.AuthLogCallback = nil, want a callback")
	}
	if sshServerConfig.BannerCallback == nil {
		t.Fatalf("sshServerConfig.BannerCallback = nil, want a callback")
	}
	if len(sshServerConfig.Ciphers) != 0 {
		t.Fatalf("len(sshServerConfig.Ciphers) = %v, want 0", len(sshServerConfig.Ciphers))
	}
	if sshServerConfig.GSSAPIWithMICConfig != nil {
		t.Fatalf("sshServerConfig.GSSAPIWithMICConfig = %+v, want nil", sshServerConfig.GSSAPIWithMICConfig)
	}
	if len(sshServerConfig.KeyExchanges) != 0 {
		t.Fatalf("len(sshServerConfig.KeyExchanges) = %v, want 0", len(sshServerConfig.KeyExchanges))
	}
	if sshServerConfig.KeyboardInteractiveCallback != nil {
		t.Fatalf("sshServerConfig.KeyboardInteractiveCallback != nil, want nil")
	}
	if len(sshServerConfig.MACs) != 0 {
		t.Fatalf("len(sshServerConfig.MACs) = %v, want 0", len(sshServerConfig.MACs))
	}
	if sshServerConfig.MaxAuthTries != 0 {
		t.Fatalf("sshServerConfig.MaxAuthTries = %v, want 0", sshServerConfig.MaxAuthTries)
	}
	if sshServerConfig.NoClientAuth == true {
		t.Fatalf("sshServerConfig.NoClientAuth = true, want false")
	}
	if sshServerConfig.PasswordCallback == nil {
		t.Fatalf("sshServerConfig.PasswordCallback = nil, want a callback")
	}
	if sshServerConfig.PublicKeyCallback == nil {
		t.Fatalf("sshServerConfig.PublicKeyCallback = nil, want a callback")
	}
	if sshServerConfig.Rand != nil {
		t.Fatalf("sshServerConfig.Rand = %v, want a nil", sshServerConfig.Rand)
	}
	if sshServerConfig.RekeyThreshold != 0 {
		t.Fatalf("sshServerConfig.RekeyThreshold = %v, want 0", sshServerConfig.RekeyThreshold)
	}
	if sshServerConfig.ServerVersion != "SSH-2.0-sshesame" {
		t.Fatalf("sshServerConfig.ServerVersion = %v, want SSH-2.0-sshesame", sshServerConfig.ServerVersion)
	}

	logFile, err := cfg.setupLogging()
	if err != nil {
		t.Fatalf("Failed to setup logging: %v", err)
	}
	if logFile != nil {
		defer logFile.Close()
		t.Fatalf("cfg.setupLogging() = %v, want nil", logFile)
	}
	if logrus.StandardLogger().Out != os.Stdout {
		t.Fatalf("logrus.StandardLogger().Out = %v, want %v", logrus.StandardLogger().Out, os.Stdout)
	}
	if _, ok := logrus.StandardLogger().Formatter.(*logrus.TextFormatter); !ok {
		t.Fatalf("Type of logrus.StandardLogger().Formatter = %T, want *logrus.TextFormatter", logrus.StandardLogger().Formatter)
	}
}

func TestUserConfigNoKeys(t *testing.T) {
	configFileName := path.Join(t.TempDir(), "no_keys.yaml")
	logFileName := path.Join(t.TempDir(), "sshesame.log")
	if err := ioutil.WriteFile(configFileName, []byte(fmt.Sprintf(`
listenaddress: 0.0.0.0:22
jsonlogging: true
logfile: %v
rekeythreshold: 123
keyexchanges: [kex]
ciphers: [cipher]
macs: [mac]
noclientauth: true
maxauthtries: 234
serverversion: SSH-2.0-test
banner:
passwordauth:
  enabled: false
  accepted: false
publickeyauth:
  enabled: false
  accepted: true
keyboardinteractiveauth:
  enabled: true
  accepted: true
  instruction: instruction1
  questions:
  - text: q1
    echo: true
  - text: q2
    echo: false`, logFileName)), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	dataDir := path.Join(t.TempDir(), "subdir")
	cfg, err := getConfig(configFileName, dataDir)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := config{
		ListenAddress: "0.0.0.0:22",
		HostKeys: []string{
			path.Join(dataDir, "host_rsa_key"),
			path.Join(dataDir, "host_ecdsa_key"),
			path.Join(dataDir, "host_ed25519_key"),
		},
		JSONLogging:    true,
		LogFile:        logFileName,
		RekeyThreshold: 123,
		KeyExchanges:   []string{"kex"},
		Ciphers:        []string{"cipher"},
		MACs:           []string{"mac"},
		NoClientAuth:   true,
		MaxAuthTries:   234,
		ServerVersion:  "SSH-2.0-test",
		Banner:         "",
	}
	expectedConfig.PublicKeyAuth.Accepted = true
	expectedConfig.KeyboardInteractiveAuth.Enabled = true
	expectedConfig.KeyboardInteractiveAuth.Accepted = true
	expectedConfig.KeyboardInteractiveAuth.Instruction = "instruction1"
	expectedConfig.KeyboardInteractiveAuth.Questions = make([]struct {
		Text string
		Echo bool
	}, 2)
	expectedConfig.KeyboardInteractiveAuth.Questions[0].Text = "q1"
	expectedConfig.KeyboardInteractiveAuth.Questions[0].Echo = true
	expectedConfig.KeyboardInteractiveAuth.Questions[1].Text = "q2"
	expectedConfig.KeyboardInteractiveAuth.Questions[1].Echo = false
	if !reflect.DeepEqual(*cfg, expectedConfig) {
		t.Fatalf("Default getConfig() = %+v, want %+v", *cfg, expectedConfig)
	}
	for _, hostKeyFileName := range cfg.HostKeys {
		hostKeyBytes, err := ioutil.ReadFile(hostKeyFileName)
		if err != nil {
			t.Fatalf("Failed to read host key %v: %v", hostKeyFileName, err)
		}
		signer, err := ssh.ParsePrivateKey(hostKeyBytes)
		if err != nil {
			t.Fatalf("Failed to parse host key %v: %v", hostKeyFileName, err)
		}
		expectedKeyType, ok := map[string]string{"host_rsa_key": "ssh-rsa", "host_ecdsa_key": "ecdsa-sha2-nistp256", "host_ed25519_key": "ssh-ed25519"}[path.Base(hostKeyFileName)]
		if !ok {
			t.Fatalf("Unexpected key file name %v", hostKeyFileName)
		}
		if signer.PublicKey().Type() != expectedKeyType {
			t.Fatalf("host key type = %v, want %v", signer.PublicKey().Type(), expectedKeyType)
		}
	}

	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		t.Fatalf("Failed to create SSH server config: %v", err)
	}
	if sshServerConfig.AuthLogCallback == nil {
		t.Fatalf("sshServerConfig.AuthLogCallback = nil, want a callback")
	}
	if sshServerConfig.BannerCallback != nil {
		t.Fatalf("sshServerConfig.BannerCallback != nil, want nil")
	}
	if !reflect.DeepEqual(sshServerConfig.Ciphers, []string{"cipher"}) {
		t.Fatalf("sshServerConfig.Ciphers = %v, want %v", sshServerConfig.Ciphers, []string{"cipher1"})
	}
	if sshServerConfig.GSSAPIWithMICConfig != nil {
		t.Fatalf("sshServerConfig.GSSAPIWithMICConfig = %+v, want nil", sshServerConfig.GSSAPIWithMICConfig)
	}
	if !reflect.DeepEqual(sshServerConfig.KeyExchanges, []string{"kex"}) {
		t.Fatalf("sshServerConfig.KeyExchanges = %v, want %v", len(sshServerConfig.KeyExchanges), []string{"kex1"})
	}
	if sshServerConfig.KeyboardInteractiveCallback == nil {
		t.Fatalf("sshServerConfig.KeyboardInteractiveCallback = nil, want a callback")
	}
	if !reflect.DeepEqual(sshServerConfig.MACs, []string{"mac"}) {
		t.Fatalf("sshServerConfig.MACs = %v, want %v", len(sshServerConfig.MACs), []string{"mac1"})
	}
	if sshServerConfig.MaxAuthTries != 234 {
		t.Fatalf("sshServerConfig.MaxAuthTries = %v, want 234", sshServerConfig.MaxAuthTries)
	}
	if sshServerConfig.NoClientAuth == false {
		t.Fatalf("sshServerConfig.NoClientAuth = false, want true")
	}
	if sshServerConfig.PasswordCallback != nil {
		t.Fatalf("sshServerConfig.PasswordCallback != nil, want nil")
	}
	if sshServerConfig.PublicKeyCallback != nil {
		t.Fatalf("sshServerConfig.PublicKeyCallback != nil, want nil")
	}
	if sshServerConfig.Rand != nil {
		t.Fatalf("sshServerConfig.Rand = %v, want a nil", sshServerConfig.Rand)
	}
	if sshServerConfig.RekeyThreshold != 123 {
		t.Fatalf("sshServerConfig.RekeyThreshold = %v, want 123", sshServerConfig.RekeyThreshold)
	}
	if sshServerConfig.ServerVersion != "SSH-2.0-test" {
		t.Fatalf("sshServerConfig.ServerVersion = %v, want SSH-2.0-test", sshServerConfig.ServerVersion)
	}

	logFile, err := cfg.setupLogging()
	if err != nil {
		t.Fatalf("Failed to setup logging: %v", err)
	}
	if logFile == nil {
		t.Fatalf("cfg.setupLogging() = nil, want a file")
	}
	defer logFile.Close()
	if logrus.StandardLogger().Out != logFile {
		t.Fatalf("logrus.StandardLogger().Out = %v, want %v", logrus.StandardLogger().Out, os.Stdout)
	}
	if _, ok := logrus.StandardLogger().Formatter.(*logrus.JSONFormatter); !ok {
		t.Fatalf("Type of logrus.StandardLogger().Formatter = %T, want *logrus.JSONFormatter", logrus.StandardLogger().Formatter)
	}
}

func TestUserConfigWithKeys(t *testing.T) {
	configFileName := path.Join(t.TempDir(), "no_keys.yaml")
	if err := ioutil.WriteFile(configFileName, []byte(`
hostkeys: [/some/key, /some/other/key]
banner: |-
  Hey
  Yo!`), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	dataDir := t.TempDir()
	cfg, err := getConfig(configFileName, dataDir)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := config{
		ListenAddress: "127.0.0.1:2022",
		HostKeys:      []string{"/some/key", "/some/other/key"},
		ServerVersion: "SSH-2.0-sshesame",
		Banner:        "Hey\r\nYo!\r\n",
	}
	expectedConfig.PasswordAuth.Enabled = true
	expectedConfig.PasswordAuth.Accepted = true
	expectedConfig.PublicKeyAuth.Enabled = true
	if !reflect.DeepEqual(*cfg, expectedConfig) {
		t.Fatalf("Default getConfig() = %+v, want %+v", *cfg, expectedConfig)
	}
	files, err := ioutil.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("Failed to list directory %v: %v", dataDir, err)
	}
	if len(files) != 0 {
		t.Fatalf("number of files in the data directory = %v, want 0", len(files))
	}

	sshServerConfig, err := cfg.createSSHServerConfig()
	if err == nil {
		log.Fatalf("SSH server config creation expected to fail (host keys don't exist) but didn't. Config: %+v", sshServerConfig)
	}

	logFile, err := cfg.setupLogging()
	if err != nil {
		t.Fatalf("Failed to setup logging: %v", err)
	}
	if logFile != nil {
		defer logFile.Close()
		t.Fatalf("cfg.setupLogging() = %v, want nil", logFile)
	}
	if logrus.StandardLogger().Out != os.Stdout {
		t.Fatalf("logrus.StandardLogger().Out = %v, want %v", logrus.StandardLogger().Out, os.Stdout)
	}
	if _, ok := logrus.StandardLogger().Formatter.(*logrus.TextFormatter); !ok {
		t.Fatalf("Type of logrus.StandardLogger().Formatter = %T, want *logrus.TextFormatter", logrus.StandardLogger().Formatter)
	}
}

func TestNewLogFile(t *testing.T) {
	logFileName := path.Join(t.TempDir(), "new.log")
	if _, err := os.Stat(logFileName); err == nil {
		t.Fatalf("os.Stat(logFile) = %v, want an error", err)
	}
	cfg := config{LogFile: logFileName}
	logFile, err := cfg.setupLogging()
	if err != nil {
		t.Fatalf("Failed to setup logging: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	logrus.Infoln("test")
	logFile.Close()
	logs, err := ioutil.ReadFile(logFileName)
	if err != nil || string(logs) != "level=info msg=test\n" {
		t.Fatalf("ioutil.ReadFile(logFileName) = %v, %v, want \"level=info msg=test\n\", nil", string(logs), err)
	}
}

func TestExistingLogFile(t *testing.T) {
	logFileName := path.Join(t.TempDir(), "existing.log")
	if err := ioutil.WriteFile(logFileName, []byte("previous_test\n"), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	cfg := config{LogFile: logFileName}
	logFile, err := cfg.setupLogging()
	if err != nil {
		t.Fatalf("Failed to setup logging: %v", err)
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	logrus.Infoln("test")
	logFile.Close()
	logs, err := ioutil.ReadFile(logFileName)
	if err != nil || string(logs) != "previous_test\nlevel=info msg=test\n" {
		t.Fatalf("ioutil.ReadFile(logFileName) = %v, %v, want \"level=info msg=test\n\", nil", string(logs), err)
	}
}
