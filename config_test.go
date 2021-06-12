package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type mockPublicKey struct {
	signature keySignature
}

func (publicKey mockPublicKey) Type() string {
	return publicKey.signature.String()
}

func (publicKey mockPublicKey) Marshal() []byte {
	return nil
}

func (publicKey mockPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	return nil
}

type mockSigner struct {
	signature keySignature
}

func (signer mockSigner) PublicKey() ssh.PublicKey {
	return mockPublicKey(signer)
}

func (signer mockSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return nil, errors.New("")
}

type mockKeyType struct {
	keys map[string]keySignature
}

func (key *mockKeyType) generate(dataDir string, signature keySignature) (string, error) {
	keyFile := path.Join(dataDir, fmt.Sprintf("host_%v_key", signature))
	if key.keys == nil {
		key.keys = map[string]keySignature{}
	}
	key.keys[keyFile] = signature
	return keyFile, nil
}

func (key *mockKeyType) load(keyFile string) (ssh.Signer, error) {
	result, ok := key.keys[keyFile]
	if !ok {
		return nil, errors.New("")
	}
	return mockSigner{result}, nil
}

func (key *mockKeyType) verifyDefaultKeys(dataDir string, t *testing.T) {
	expectedKeys := map[string]keySignature{
		path.Join(dataDir, "host_rsa_key"):     rsa_key,
		path.Join(dataDir, "host_ecdsa_key"):   ecdsa_key,
		path.Join(dataDir, "host_ed25519_key"): ed25519_key,
	}
	if !reflect.DeepEqual(key.keys, expectedKeys) {
		t.Fatalf("keys=%v, want %v", key.keys, expectedKeys)
	}
	for file, signature := range key.keys {
		signer, err := key.load(file)
		if err != nil {
			t.Fatalf("Failed to load key: %v", err)
		}
		expectedKeyType := signature.String()
		if signer.PublicKey().Type() != expectedKeyType {
			t.Errorf("signer.PublicKey().Type()=%v, want %v", signer.PublicKey().Type(), expectedKeyType)
		}
	}
}

type mockFile struct {
	closed bool
}

func (file *mockFile) Write(p []byte) (n int, err error) {
	return 0, errors.New("")
}

func (file *mockFile) Close() error {
	if file.closed {
		return errors.New("")
	}
	file.closed = true
	return nil
}

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

func TestDefaultConfig(t *testing.T) {
	dataDir := "test"
	key := &mockKeyType{}
	log.SetOutput(ioutil.Discard)
	cfg, err := getConfig("", dataDir, key)
	log.SetOutput(os.Stderr)
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
	key.verifyDefaultKeys(dataDir, t)
}

func TestUserConfigDefaultKeys(t *testing.T) {
	logFile := path.Join(t.TempDir(), "test.log")
	cfgString := fmt.Sprintf(`
listen_address: 0.0.0.0:22
log_file: %v
json_logging: true
rekey_threshold: 123
key_exchanges: [kex]
ciphers: [cipher]
macs: [mac]
no_client_auth: true
max_auth_tries: 234
password_auth:
  enabled: false
  accepted: false
public_key_auth:
  enabled: false
  accepted: true
keyboard_interactive_auth:
  enabled: true
  accepted: true
  instruction: instruction
  questions:
  - text: q1
    echo: true
  - text: q2
    echo: false
server_version: SSH-2.0-test
banner:
`, logFile)
	dataDir := "test"
	key := &mockKeyType{}
	log.SetOutput(ioutil.Discard)
	cfg, err := getConfig(cfgString, dataDir, key)
	log.SetOutput(os.Stderr)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := &config{
		ListenAddress:  "0.0.0.0:22",
		LogFile:        logFile,
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
	expectedConfig.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	verifyConfig(cfg, expectedConfig, t)
	key.verifyDefaultKeys(dataDir, t)
}

func TestUserConfigCustomKeys(t *testing.T) {
	keyFile := "rsa.key"
	cfgString := fmt.Sprintf(`
host_keys: [%v]
`, keyFile)
	dataDir := "test"
	key := &mockKeyType{map[string]keySignature{keyFile: rsa_key}}
	cfg, err := getConfig(cfgString, dataDir, key)
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
	expectedKeys := map[string]keySignature{
		keyFile: rsa_key,
	}
	if !reflect.DeepEqual(key.keys, expectedKeys) {
		t.Errorf("key.keys=%v, want %v", key.keys, expectedKeys)
	}
}

func TestSetupLoggingOldHandleClosed(t *testing.T) {
	file := &mockFile{}
	cfg := &config{logFileHandle: file}
	if err := cfg.setupLogging(); err != nil {
		t.Fatalf("Failed to set up logging: %v", err)
	}
	if !file.closed {
		t.Errorf("file.closed=false, want true")
	}
}

func TestPKCS8fileKey(t *testing.T) {
	baseDir := t.TempDir()
	for signature, keyType := range map[keySignature]string{
		rsa_key:     "ssh-rsa",
		ecdsa_key:   "ecdsa-sha2-nistp256",
		ed25519_key: "ssh-ed25519",
	} {
		dataDir := path.Join(baseDir, keyType)
		log.SetOutput(ioutil.Discard)
		keyFile, err := pkcs8fileKey{}.generate(dataDir, signature)
		log.SetOutput(os.Stderr)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		signer, err := pkcs8fileKey{}.load(keyFile)
		if err != nil {
			t.Fatalf("Failed to load key: %v", err)
		}
		files, err := ioutil.ReadDir(dataDir)
		if err != nil {
			t.Fatalf("Failed to list directory: %v", err)
		}
		if len(files) != 1 {
			t.Errorf("len(files)=%v, want 1", len(files))
		}
		if signer.PublicKey().Type() != keyType {
			t.Errorf("signer.PublicKey().Type()=%v, want %v", signer.PublicKey().Type(), keyType)
		}
	}
}

func TestExistingPKCS8fileKey(t *testing.T) {
	dataDir := t.TempDir()
	log.SetOutput(ioutil.Discard)
	oldKeyFile, err := pkcs8fileKey{}.generate(dataDir, ed25519_key)
	log.SetOutput(os.Stderr)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	oldKey, err := ioutil.ReadFile(oldKeyFile)
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}
	newKeyFile, err := pkcs8fileKey{}.generate(dataDir, ed25519_key)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	newKey, err := ioutil.ReadFile(newKeyFile)
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}
	if !reflect.DeepEqual(oldKey, newKey) {
		t.Errorf("oldKey!=newKey")
	}
}
