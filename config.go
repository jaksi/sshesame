package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

type authConfig struct {
	Enabled  bool `yaml:"enabled"`
	Accepted bool `yaml:"accepted"`
}

type keyboardInteractiveAuthQuestion struct {
	Text string `yaml:"text"`
	Echo bool   `yaml:"echo"`
}

type keyboardInteractiveAuthConfig struct {
	authConfig  `yaml:",inline"`
	Instruction string                            `yaml:"instruction"`
	Questions   []keyboardInteractiveAuthQuestion `yaml:"questions"`
}

type config struct {
	ListenAddress           string                        `yaml:"listen_address"`
	LogFile                 string                        `yaml:"log_file"`
	JSONLogging             bool                          `yaml:"json_logging"`
	RekeyThreshold          uint64                        `yaml:"rekey_threshold"`
	KeyExchanges            []string                      `yaml:"key_exchanges"`
	Ciphers                 []string                      `yaml:"ciphers"`
	MACs                    []string                      `yaml:"macs"`
	HostKeys                []string                      `yaml:"host_keys"`
	NoClientAuth            bool                          `yaml:"no_client_auth"`
	MaxAuthTries            int                           `yaml:"max_auth_tries"`
	PasswordAuth            authConfig                    `yaml:"password_auth"`
	PublicKeyAuth           authConfig                    `yaml:"public_key_auth"`
	KeyboardInteractiveAuth keyboardInteractiveAuthConfig `yaml:"keyboard_interactive_auth"`
	ServerVersion           string                        `yaml:"server_version"`
	Banner                  string                        `yaml:"banner"`

	parsedHostKeys []ssh.Signer
	sshConfig      *ssh.ServerConfig
	logFileHandle  io.WriteCloser
}

func getDefaultConfig() *config {
	cfg := &config{
		ListenAddress: "127.0.0.1:2022",
		ServerVersion: "SSH-2.0-sshesame",
		Banner:        "This is an SSH honeypot. Everything is logged and monitored.",
	}
	cfg.PasswordAuth.Enabled = true
	cfg.PasswordAuth.Accepted = true
	cfg.PublicKeyAuth.Enabled = true
	return cfg
}

type keySignature int

const (
	rsa_key keySignature = iota
	ecdsa_key
	ed25519_key
)

func (signature keySignature) String() string {
	switch signature {
	case rsa_key:
		return "rsa"
	case ecdsa_key:
		return "ecdsa"
	case ed25519_key:
		return "ed25519"
	default:
		return "unknown"
	}
}

type keyType interface {
	generate(dataDir string, signature keySignature) (string, error)
	load(keyFile string) (ssh.Signer, error)
}

type pkcs8fileKey struct{}

func (pkcs8fileKey) generate(dataDir string, signature keySignature) (string, error) {
	keyFile := path.Join(dataDir, fmt.Sprintf("host_%v_key", signature))
	if _, err := os.Stat(keyFile); err == nil {
		return keyFile, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	log.Println("Host key", keyFile, "not found, generating it")
	if _, err := os.Stat(path.Dir(keyFile)); os.IsNotExist(err) {
		if err := os.MkdirAll(path.Dir(keyFile), 0755); err != nil {
			return "", err
		}
	}
	var key interface{}
	err := errors.New("unsupported key type")
	switch signature {
	case rsa_key:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case ecdsa_key:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ed25519_key:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		return "", err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := ioutil.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		return "", err
	}
	return keyFile, nil
}

func (pkcs8fileKey) load(keyFile string) (ssh.Signer, error) {
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(keyBytes)
}

func (cfg *config) setDefaultHostKeys(dataDir string, key keyType, signatures []keySignature) error {
	for _, signature := range signatures {
		keyFile, err := key.generate(dataDir, signature)
		if err != nil {
			return err
		}
		cfg.HostKeys = append(cfg.HostKeys, keyFile)
	}
	return nil
}

func (cfg *config) parseHostKeys(key keyType) error {
	for _, keyFile := range cfg.HostKeys {
		signer, err := key.load(keyFile)
		if err != nil {
			return err
		}
		cfg.parsedHostKeys = append(cfg.parsedHostKeys, signer)
	}
	return nil
}

func (cfg *config) setupSSHConfig(key keyType) error {
	sshConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			RekeyThreshold: cfg.RekeyThreshold,
			KeyExchanges:   cfg.KeyExchanges,
			Ciphers:        cfg.Ciphers,
			MACs:           cfg.MACs,
		},
		NoClientAuth:                cfg.NoClientAuth,
		MaxAuthTries:                cfg.MaxAuthTries,
		AuthLogCallback:             authLogCallback,
		ServerVersion:               cfg.ServerVersion,
		PasswordCallback:            cfg.getPasswordCallback(),
		PublicKeyCallback:           cfg.getPublicKeyCallback(),
		KeyboardInteractiveCallback: cfg.getKeyboardInteractiveCallback(),
		BannerCallback:              cfg.getBannerCallback(),
	}
	if err := cfg.parseHostKeys(key); err != nil {
		return err
	}
	for _, key := range cfg.parsedHostKeys {
		sshConfig.AddHostKey(key)
	}
	cfg.sshConfig = sshConfig
	return nil
}

func (cfg *config) setupLogging() error {
	if cfg.logFileHandle != nil {
		cfg.logFileHandle.Close()
	}
	if cfg.LogFile != "" {
		logFile, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		logrus.SetOutput(logFile)
		cfg.logFileHandle = logFile
	} else {
		logrus.SetOutput(os.Stdout)
		cfg.logFileHandle = nil
	}
	if cfg.JSONLogging {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{})
	}
	return nil
}

func getConfig(configString string, dataDir string, key keyType) (*config, error) {
	cfg := getDefaultConfig()

	if err := yaml.UnmarshalStrict([]byte(configString), cfg); err != nil {
		return nil, err
	}

	if len(cfg.HostKeys) == 0 {
		log.Println("No host keys configured, using keys at", dataDir)
		if err := cfg.setDefaultHostKeys(dataDir, key, []keySignature{rsa_key, ecdsa_key, ed25519_key}); err != nil {
			return nil, err
		}
	}

	if err := cfg.setupSSHConfig(key); err != nil {
		return nil, err
	}
	if err := cfg.setupLogging(); err != nil {
		return nil, err
	}

	return cfg, nil
}
