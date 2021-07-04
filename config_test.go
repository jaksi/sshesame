package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"reflect"
	"testing"

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
	if !reflect.DeepEqual(cfg.Server, expected.Server) {
		t.Errorf("Server=%v, want %v", cfg.Server, expected.Server)
	}
	if !reflect.DeepEqual(cfg.Logging, expected.Logging) {
		t.Errorf("Logging=%v, want %v", cfg.Logging, expected.Logging)
	}
	if !reflect.DeepEqual(cfg.Auth, expected.Auth) {
		t.Errorf("Auth=%v, want %v", cfg.Auth, expected.Auth)
	}
	if !reflect.DeepEqual(cfg.SSHProto, expected.SSHProto) {
		t.Errorf("SSHProto=%v, want %v", cfg.SSHProto, expected.SSHProto)
	}

	if cfg.sshConfig.RekeyThreshold != expected.SSHProto.RekeyThreshold {
		t.Errorf("sshConfig.RekeyThreshold=%v, want %v", cfg.sshConfig.RekeyThreshold, expected.SSHProto.RekeyThreshold)
	}
	if !reflect.DeepEqual(cfg.sshConfig.KeyExchanges, expected.SSHProto.KeyExchanges) {
		t.Errorf("sshConfig.KeyExchanges=%v, want %v", cfg.sshConfig.KeyExchanges, expected.SSHProto.KeyExchanges)
	}
	if !reflect.DeepEqual(cfg.sshConfig.Ciphers, expected.SSHProto.Ciphers) {
		t.Errorf("sshConfig.Ciphers=%v, want %v", cfg.sshConfig.Ciphers, expected.SSHProto.Ciphers)
	}
	if !reflect.DeepEqual(cfg.sshConfig.MACs, expected.SSHProto.MACs) {
		t.Errorf("sshConfig.MACs=%v, want %v", cfg.sshConfig.MACs, expected.SSHProto.MACs)
	}
	if cfg.sshConfig.NoClientAuth != expected.Auth.NoAuth {
		t.Errorf("sshConfig.NoClientAuth=%v, want %v", cfg.sshConfig.NoClientAuth, expected.Auth.NoAuth)
	}
	if cfg.sshConfig.MaxAuthTries != expected.Auth.MaxTries {
		t.Errorf("sshConfig.MaxAuthTries=%v, want %v", cfg.sshConfig.MaxAuthTries, expected.Auth.MaxTries)
	}
	if (cfg.sshConfig.PasswordCallback != nil) != expected.Auth.PasswordAuth.Enabled {
		t.Errorf("sshConfig.PasswordCallback=%v, want %v", cfg.sshConfig.PasswordCallback != nil, expected.Auth.PasswordAuth.Enabled)
	}
	if (cfg.sshConfig.PublicKeyCallback != nil) != expected.Auth.PublicKeyAuth.Enabled {
		t.Errorf("sshConfig.PasswordCallback=%v, want %v", cfg.sshConfig.PublicKeyCallback != nil, expected.Auth.PublicKeyAuth.Enabled)
	}
	if (cfg.sshConfig.KeyboardInteractiveCallback != nil) != expected.Auth.KeyboardInteractiveAuth.Enabled {
		t.Errorf("sshConfig.KeyboardInteractiveCallback=%v, want %v", cfg.sshConfig.KeyboardInteractiveCallback != nil, expected.Auth.KeyboardInteractiveAuth.Enabled)
	}
	if cfg.sshConfig.AuthLogCallback == nil {
		t.Errorf("sshConfig.AuthLogCallback=nil, want a callback")
	}
	if cfg.sshConfig.ServerVersion != expected.SSHProto.Version {
		t.Errorf("sshConfig.ServerVersion=%v, want %v", cfg.sshConfig.ServerVersion, expected.SSHProto.Version)
	}
	if (cfg.sshConfig.BannerCallback != nil) != (expected.SSHProto.Banner != "") {
		t.Errorf("sshConfig.BannerCallback=%v, want %v", cfg.sshConfig.BannerCallback != nil, expected.SSHProto.Banner != "")
	}
	if cfg.sshConfig.GSSAPIWithMICConfig != nil {
		t.Errorf("sshConfig.GSSAPIWithMICConfig=%v, want nil", cfg.sshConfig.GSSAPIWithMICConfig)
	}
	if len(cfg.parsedHostKeys) != len(expected.Server.HostKeys) {
		t.Errorf("len(parsedHostKeys)=%v, want %v", len(cfg.parsedHostKeys), len(expected.Server.HostKeys))
	}

	if expected.Logging.File == "" {
		if cfg.logFileHandle != nil {
			t.Errorf("logFileHandle=%v, want nil", cfg.logFileHandle)
		}
	} else {
		if cfg.logFileHandle == nil {
			t.Errorf("logFileHandle=nil, want a file")
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	dataDir := "test"
	key := &mockKeyType{}
	cfg, err := getConfig("", dataDir, key)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := &config{}
	expectedConfig.Server.ListenAddress = "127.0.0.1:2022"
	expectedConfig.Server.HostKeys = []string{
		path.Join(dataDir, "host_rsa_key"),
		path.Join(dataDir, "host_ecdsa_key"),
		path.Join(dataDir, "host_ed25519_key"),
	}
	expectedConfig.Auth.PasswordAuth.Enabled = true
	expectedConfig.Auth.PasswordAuth.Accepted = true
	expectedConfig.Auth.PublicKeyAuth.Enabled = true
	expectedConfig.SSHProto.Version = "SSH-2.0-sshesame"
	expectedConfig.SSHProto.Banner = "This is an SSH honeypot. Everything is logged and monitored."
	verifyConfig(cfg, expectedConfig, t)
	key.verifyDefaultKeys(dataDir, t)
}

func TestUserConfigDefaultKeys(t *testing.T) {
	logFile := path.Join(t.TempDir(), "test.log")
	cfgString := fmt.Sprintf(`
server:
  listen_address: 0.0.0.0:22
logging:
  file: %v
  json: true
auth:
  max_tries: 234
  no_auth: true
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
ssh_proto:
  version: SSH-2.0-test
  banner:
  rekey_threshold: 123
  key_exchanges: [kex]
  ciphers: [cipher]
  macs: [mac]
`, logFile)
	dataDir := "test"
	key := &mockKeyType{}
	cfg, err := getConfig(cfgString, dataDir, key)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	if cfg.logFileHandle != nil {
		cfg.logFileHandle.Close()
	}
	expectedConfig := &config{}
	expectedConfig.Server.ListenAddress = "0.0.0.0:22"
	expectedConfig.Server.HostKeys = []string{
		path.Join(dataDir, "host_rsa_key"),
		path.Join(dataDir, "host_ecdsa_key"),
		path.Join(dataDir, "host_ed25519_key"),
	}
	expectedConfig.Logging.File = logFile
	expectedConfig.Logging.JSON = true
	expectedConfig.Auth.MaxTries = 234
	expectedConfig.Auth.NoAuth = true
	expectedConfig.Auth.PublicKeyAuth.Accepted = true
	expectedConfig.Auth.KeyboardInteractiveAuth.Enabled = true
	expectedConfig.Auth.KeyboardInteractiveAuth.Accepted = true
	expectedConfig.Auth.KeyboardInteractiveAuth.Instruction = "instruction"
	expectedConfig.Auth.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	expectedConfig.SSHProto.Version = "SSH-2.0-test"
	expectedConfig.SSHProto.RekeyThreshold = 123
	expectedConfig.SSHProto.KeyExchanges = []string{"kex"}
	expectedConfig.SSHProto.Ciphers = []string{"cipher"}
	expectedConfig.SSHProto.MACs = []string{"mac"}
	verifyConfig(cfg, expectedConfig, t)
	key.verifyDefaultKeys(dataDir, t)
}

func TestUserConfigCustomKeys(t *testing.T) {
	keyFile := "rsa.key"
	cfgString := fmt.Sprintf(`
server:
  host_keys: [%v]
`, keyFile)
	dataDir := "test"
	key := &mockKeyType{map[string]keySignature{keyFile: rsa_key}}
	cfg, err := getConfig(cfgString, dataDir, key)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := &config{}
	expectedConfig.Server.ListenAddress = "127.0.0.1:2022"
	expectedConfig.Server.HostKeys = []string{keyFile}
	expectedConfig.Auth.PasswordAuth.Enabled = true
	expectedConfig.Auth.PasswordAuth.Accepted = true
	expectedConfig.Auth.PublicKeyAuth.Enabled = true
	expectedConfig.SSHProto.Version = "SSH-2.0-sshesame"
	expectedConfig.SSHProto.Banner = "This is an SSH honeypot. Everything is logged and monitored."
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
		keyFile, err := pkcs8fileKey{}.generate(dataDir, signature)
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
	oldKeyFile, err := pkcs8fileKey{}.generate(dataDir, ed25519_key)
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
