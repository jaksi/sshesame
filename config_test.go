package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func verifyConfig(cfg *config, expected *config, t *testing.T) {
	if cfg.ListenAddress != expected.ListenAddress {
		t.Errorf("ListenAddress=%v, want %v", cfg.ListenAddress, expected.ListenAddress)
	}
	if cfg.LogFile != expected.LogFile {
		t.Errorf("LogFile=%v, want %v", cfg.LogFile, expected.LogFile)
	}
	if cfg.JSONLogging != expected.JSONLogging {
		t.Errorf("JSONLogging=%v, want %v", cfg.JSONLogging, expected.JSONLogging)
	}
	if cfg.RekeyThreshold != expected.RekeyThreshold {
		t.Errorf("RekeyThreshold=%v, want %v", cfg.RekeyThreshold, expected.RekeyThreshold)
	}
	if !reflect.DeepEqual(cfg.KeyExchanges, expected.KeyExchanges) {
		t.Errorf("KeyExchanges=%v, want %v", cfg.KeyExchanges, expected.KeyExchanges)
	}
	if !reflect.DeepEqual(cfg.Ciphers, expected.Ciphers) {
		t.Errorf("Ciphers=%v, want %v", cfg.Ciphers, expected.Ciphers)
	}
	if !reflect.DeepEqual(cfg.MACs, expected.MACs) {
		t.Errorf("MACs=%v, want %v", cfg.MACs, expected.MACs)
	}
	if !reflect.DeepEqual(cfg.HostKeys, expected.HostKeys) {
		t.Errorf("HostKeys=%v, want %v", cfg.HostKeys, expected.HostKeys)
	}
	if cfg.NoClientAuth != expected.NoClientAuth {
		t.Errorf("NoClientAuth=%v, want %v", cfg.NoClientAuth, expected.NoClientAuth)
	}
	if cfg.MaxAuthTries != expected.MaxAuthTries {
		t.Errorf("MaxAuthTries=%v, want %v", cfg.MaxAuthTries, expected.MaxAuthTries)
	}
	if !reflect.DeepEqual(cfg.PasswordAuth, expected.PasswordAuth) {
		t.Errorf("PasswordAuth=%v, want %v", cfg.PasswordAuth, expected.PasswordAuth)
	}
	if !reflect.DeepEqual(cfg.PublicKeyAuth, expected.PublicKeyAuth) {
		t.Errorf("PublicKeyAuth=%v, want %v", cfg.PublicKeyAuth, expected.PublicKeyAuth)
	}
	if !reflect.DeepEqual(cfg.KeyboardInteractiveAuth, expected.KeyboardInteractiveAuth) {
		t.Errorf("KeyboardInteractiveAuth=%v, want %v", cfg.KeyboardInteractiveAuth, expected.KeyboardInteractiveAuth)
	}
	if cfg.ServerVersion != expected.ServerVersion {
		t.Errorf("ServerVersion=%v, want %v", cfg.ServerVersion, expected.ServerVersion)
	}
	if cfg.Banner != expected.Banner {
		t.Errorf("Banner=%v, want %v", cfg.Banner, expected.Banner)
	}

	if cfg.sshConfig.RekeyThreshold != expected.RekeyThreshold {
		t.Errorf("sshConfig.RekeyThreshold=%v, want %v", cfg.sshConfig.RekeyThreshold, expected.RekeyThreshold)
	}
	if !reflect.DeepEqual(cfg.sshConfig.KeyExchanges, expected.KeyExchanges) {
		t.Errorf("sshConfig.KeyExchanges=%v, want %v", cfg.sshConfig.KeyExchanges, expected.KeyExchanges)
	}
	if !reflect.DeepEqual(cfg.sshConfig.Ciphers, expected.Ciphers) {
		t.Errorf("sshConfig.Ciphers=%v, want %v", cfg.sshConfig.Ciphers, expected.Ciphers)
	}
	if !reflect.DeepEqual(cfg.sshConfig.MACs, expected.MACs) {
		t.Errorf("sshConfig.MACs=%v, want %v", cfg.sshConfig.MACs, expected.MACs)
	}
	if cfg.sshConfig.NoClientAuth != expected.NoClientAuth {
		t.Errorf("sshConfig.NoClientAuth=%v, want %v", cfg.sshConfig.NoClientAuth, expected.NoClientAuth)
	}
	if cfg.sshConfig.MaxAuthTries != expected.MaxAuthTries {
		t.Errorf("sshConfig.MaxAuthTries=%v, want %v", cfg.sshConfig.MaxAuthTries, expected.MaxAuthTries)
	}
	if (cfg.sshConfig.PasswordCallback != nil) != expected.PasswordAuth.Enabled {
		t.Errorf("sshConfig.PasswordCallback=%v, want %v", cfg.sshConfig.PasswordCallback != nil, expected.PasswordAuth.Enabled)
	}
	if (cfg.sshConfig.PublicKeyCallback != nil) != expected.PublicKeyAuth.Enabled {
		t.Errorf("sshConfig.PasswordCallback=%v, want %v", cfg.sshConfig.PublicKeyCallback != nil, expected.PublicKeyAuth.Enabled)
	}
	if (cfg.sshConfig.KeyboardInteractiveCallback != nil) != expected.KeyboardInteractiveAuth.Enabled {
		t.Errorf("sshConfig.KeyboardInteractiveCallback=%v, want %v", cfg.sshConfig.KeyboardInteractiveCallback != nil, expected.KeyboardInteractiveAuth.Enabled)
	}
	if cfg.sshConfig.AuthLogCallback == nil {
		t.Errorf("sshConfig.AuthLogCallback=nil, want a callback")
	}
	if cfg.sshConfig.ServerVersion != expected.ServerVersion {
		t.Errorf("sshConfig.ServerVersion=%v, want %v", cfg.sshConfig.ServerVersion, expected.ServerVersion)
	}
	if (cfg.sshConfig.BannerCallback != nil) != (expected.Banner != "") {
		t.Errorf("sshConfig.BannerCallback=%v, want %v", cfg.sshConfig.BannerCallback != nil, expected.Banner != "")
	}
	if cfg.sshConfig.GSSAPIWithMICConfig != nil {
		t.Errorf("sshConfig.GSSAPIWithMICConfig=%v, want nil", cfg.sshConfig.GSSAPIWithMICConfig)
	}
	if len(cfg.parsedHostKeys) != len(expected.HostKeys) {
		t.Errorf("len(parsedHostKeys)=%v, want %v", len(cfg.parsedHostKeys), len(expected.HostKeys))
	}

	if expected.LogFile == "" {
		if logrus.StandardLogger().Out != os.Stdout {
			t.Errorf("logrus.StandardLogger().Out=%v, want %v (os.Stdout)", logrus.StandardLogger().Out, os.Stdout)
		}
		if cfg.logFileHandle != nil {
			t.Errorf("logFileHandle=%v, want nil", cfg.logFileHandle)
		}
	} else {
		if logrus.StandardLogger().Out == os.Stdout {
			t.Errorf("logrus.StandardLogger().Out=%v (os.Stdout), want a file", logrus.StandardLogger().Out)
		}
		if cfg.logFileHandle != logrus.StandardLogger().Out {
			t.Errorf("logFileHandle=%v, want %v", cfg.logFileHandle, logrus.StandardLogger().Out)
		}
	}
	if expected.JSONLogging {
		if _, ok := logrus.StandardLogger().Formatter.(*logrus.JSONFormatter); !ok {
			t.Errorf("Type of logrus.StandardLogger().Formatter=%T, want *logrus.JSONFormatter", logrus.StandardLogger().Formatter)
		}
	} else {
		if _, ok := logrus.StandardLogger().Formatter.(*logrus.TextFormatter); !ok {
			t.Errorf("Type of logrus.StandardLogger().Formatter=%T, want *logrus.TextFormatter", logrus.StandardLogger().Formatter)
		}
	}
}

func verifyDefaultKeys(dataDir string, t *testing.T) {
	expectedKeys := map[string]string{
		"host_rsa_key":     "ssh-rsa",
		"host_ecdsa_key":   "ecdsa-sha2-nistp256",
		"host_ed25519_key": "ssh-ed25519",
	}
	keys, err := ioutil.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("Failed to list %v: %v", dataDir, err)
	}
	if len(keys) != len(expectedKeys) {
		t.Errorf("len(keys)=%v, want %v", len(keys), len(expectedKeys))
	}
	for _, key := range keys {
		if _, ok := expectedKeys[key.Name()]; !ok {
			t.Errorf("Unexpected key: %v", key)
		}
	}
	for keyFile, keyType := range expectedKeys {
		keyBytes, err := ioutil.ReadFile(path.Join(dataDir, keyFile))
		if err != nil {
			t.Fatalf("Can't read %v: %v", keyFile, err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			t.Fatalf("Can't parse %v: %v", keyFile, err)
		}
		if signer.PublicKey().Type() != keyType {
			t.Errorf("Type(%v)=%v, want %v", keyFile, signer.PublicKey().Type(), keyType)
		}
	}
}

func verifyNoDefaultKeys(dataDir string, t *testing.T) {
	keys, err := ioutil.ReadDir(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("Failed to list %v: %v", dataDir, err)
	}
	if len(keys) != 0 {
		t.Errorf("len(keys)=%v, want 0", len(keys))
	}
}

func TestDefaultConfig(t *testing.T) {
	dataDir := path.Join(t.TempDir(), "test")
	cfg, err := getConfig("", dataDir)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := &config{
		ListenAddress: "127.0.0.1:2022",
		HostKeys: []string{
			path.Join(dataDir, "host_rsa_key"),
			path.Join(dataDir, "host_ecdsa_key"),
			path.Join(dataDir, "host_ed25519_key"),
		},
		ServerVersion: "SSH-2.0-sshesame",
		Banner:        "This is an SSH honeypot. Everything is logged and monitored.",
	}
	expectedConfig.PasswordAuth.Enabled = true
	expectedConfig.PasswordAuth.Accepted = true
	expectedConfig.PublicKeyAuth.Enabled = true
	verifyConfig(cfg, expectedConfig, t)
	verifyDefaultKeys(dataDir, t)
}

func TestUserConfigDefaultKeys(t *testing.T) {
	configFile := path.Join(t.TempDir(), "sshesame.yaml")
	logDir := t.TempDir()
	if err := ioutil.WriteFile(configFile, []byte(fmt.Sprintf(`
listenaddress: 0.0.0.0:22
logfile: %v/test.log
jsonlogging: true
rekeythreshold: 123
keyexchanges: [kex]
ciphers: [cipher]
macs: [mac]
noclientauth: true
maxauthtries: 234
passwordauth:
  enabled: false
  accepted: false
publickeyauth:
  enabled: false
  accepted: true
keyboardinteractiveauth:
  enabled: true
  accepted: true
  instruction: instruction
  questions:
  - text: q1
    echo: true
  - text: q2
    echo: false
serverversion: SSH-2.0-test
banner:
`, logDir)), 0664); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	dataDir := path.Join(t.TempDir(), "test")
	cfg, err := getConfig(configFile, dataDir)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := &config{
		ListenAddress:  "0.0.0.0:22",
		LogFile:        fmt.Sprintf("%v/test.log", logDir),
		JSONLogging:    true,
		RekeyThreshold: 123,
		KeyExchanges:   []string{"kex"},
		Ciphers:        []string{"cipher"},
		MACs:           []string{"mac"},
		NoClientAuth:   true,
		HostKeys: []string{
			path.Join(dataDir, "host_rsa_key"),
			path.Join(dataDir, "host_ecdsa_key"),
			path.Join(dataDir, "host_ed25519_key"),
		},
		MaxAuthTries:  234,
		ServerVersion: "SSH-2.0-test",
	}
	expectedConfig.PublicKeyAuth.Accepted = true
	expectedConfig.KeyboardInteractiveAuth.Accepted = true
	expectedConfig.KeyboardInteractiveAuth.Enabled = true
	expectedConfig.KeyboardInteractiveAuth.Instruction = "instruction"
	expectedConfig.KeyboardInteractiveAuth.Questions = append(expectedConfig.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q1", true})
	expectedConfig.KeyboardInteractiveAuth.Questions = append(expectedConfig.KeyboardInteractiveAuth.Questions, struct {
		Text string
		Echo bool
	}{"q2", false})
	verifyConfig(cfg, expectedConfig, t)
	verifyDefaultKeys(dataDir, t)
}

func TestUserConfigCustomKeys(t *testing.T) {
	keyFile := path.Join(t.TempDir(), "rsa.key")
	if err := generateKey(keyFile, rsa_key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	configFile := path.Join(t.TempDir(), "sshesame.yaml")
	if err := ioutil.WriteFile(configFile, []byte(fmt.Sprintf(`
hostkeys: [%v]
`, keyFile)), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	dataDir := path.Join(t.TempDir(), "test")
	cfg, err := getConfig(configFile, dataDir)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := &config{
		ListenAddress: "127.0.0.1:2022",
		HostKeys:      []string{keyFile},
		ServerVersion: "SSH-2.0-sshesame",
		Banner:        "This is an SSH honeypot. Everything is logged and monitored.",
	}
	expectedConfig.PasswordAuth.Enabled = true
	expectedConfig.PasswordAuth.Accepted = true
	expectedConfig.PublicKeyAuth.Enabled = true
	verifyConfig(cfg, expectedConfig, t)
	verifyNoDefaultKeys(dataDir, t)
}

func TestDefaultConfigKeysExist(t *testing.T) {
	dataDir := path.Join(t.TempDir(), "test")
	keyFile := path.Join(dataDir, "host_rsa_key")
	if err := generateKey(keyFile, rsa_key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}
	if _, err := getConfig("", dataDir); err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	newKeyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}
	if !reflect.DeepEqual(keyBytes, newKeyBytes) {
		t.Errorf("newKeyBytes=%v, want %v", newKeyBytes, keyBytes)
	}
}

func TestSetupLoggingOldHandleClosed(t *testing.T) {
	file, err := os.Create(path.Join(t.TempDir(), "test.log"))
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	cfg := &config{logFileHandle: file}
	if err := cfg.setupLogging(); err != nil {
		t.Fatalf("Failed to set up logging: %v", err)
	}
	if _, err := file.WriteString("test"); err == nil {
		t.Errorf("file.WriteString()=nil, want an error (should be closed)")
	}
}
