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
	"log"
	"os"
	"path"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

type serverConfig struct {
	ListenAddress string            `yaml:"listen_address"`
	HostKeys      []string          `yaml:"host_keys"`
	TCPIPServices map[uint32]string `yaml:"tcpip_services"`
}

type loggingConfig struct {
	File           string `yaml:"file"`
	JSON           bool   `yaml:"json"`
	Timestamps     bool   `yaml:"timestamps"`
	MetricsAddress string `yaml:"metrics_address"`
	Debug          bool   `yaml:"debug"`
	SplitHostPort  bool   `yaml:"split_host_port"`
}

type commonAuthConfig struct {
	Enabled  bool `yaml:"enabled"`
	Accepted bool `yaml:"accepted"`
}

type keyboardInteractiveAuthQuestion struct {
	Text string `yaml:"text"`
	Echo bool   `yaml:"echo"`
}

type keyboardInteractiveAuthConfig struct {
	commonAuthConfig `yaml:",inline"`
	Instruction      string                            `yaml:"instruction"`
	Questions        []keyboardInteractiveAuthQuestion `yaml:"questions"`
}

type authConfig struct {
	MaxTries                int                           `yaml:"max_tries"`
	NoAuth                  bool                          `yaml:"no_auth"`
	PasswordAuth            commonAuthConfig              `yaml:"password_auth"`
	PublicKeyAuth           commonAuthConfig              `yaml:"public_key_auth"`
	KeyboardInteractiveAuth keyboardInteractiveAuthConfig `yaml:"keyboard_interactive_auth"`
}

type sshProtoConfig struct {
	Version        string   `yaml:"version"`
	Banner         string   `yaml:"banner"`
	RekeyThreshold uint64   `yaml:"rekey_threshold"`
	KeyExchanges   []string `yaml:"key_exchanges"`
	Ciphers        []string `yaml:"ciphers"`
	MACs           []string `yaml:"macs"`
}

type config struct {
	Server   serverConfig   `yaml:"server"`
	Logging  loggingConfig  `yaml:"logging"`
	Auth     authConfig     `yaml:"auth"`
	SSHProto sshProtoConfig `yaml:"ssh_proto"`

	parsedHostKeys []ssh.Signer
	sshConfig      *ssh.ServerConfig
	logFileHandle  io.WriteCloser
}

func (cfg *config) setDefaults() {
	cfg.Server.ListenAddress = "127.0.0.1:2022"
	cfg.Logging.Timestamps = true
	cfg.Auth.PasswordAuth.Enabled = true
	cfg.Auth.PasswordAuth.Accepted = true
	cfg.Auth.PublicKeyAuth.Enabled = true
	cfg.SSHProto.Version = "SSH-2.0-sshesame"
	cfg.SSHProto.Banner = "This is an SSH honeypot. Everything is logged and monitored."
}

var defaultTCPIPServices = map[uint32]string{
	25:   "SMTP",
	80:   "HTTP",
	110:  "POP3",
	587:  "SMTP",
	8080: "HTTP",
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

func generateKey(dataDir string, signature keySignature) (string, error) {
	keyFile := path.Join(dataDir, fmt.Sprintf("host_%v_key", signature))
	if _, err := os.Stat(keyFile); err == nil {
		return keyFile, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	infoLogger.Printf("Host key %q not found, generating it", keyFile)
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
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		return "", err
	}
	return keyFile, nil
}

func loadKey(keyFile string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(keyBytes)
}

func (cfg *config) setDefaultHostKeys(dataDir string, signatures []keySignature) error {
	for _, signature := range signatures {
		keyFile, err := generateKey(dataDir, signature)
		if err != nil {
			return err
		}
		cfg.Server.HostKeys = append(cfg.Server.HostKeys, keyFile)
	}
	return nil
}

func (cfg *config) parseHostKeys() error {
	for _, keyFile := range cfg.Server.HostKeys {
		signer, err := loadKey(keyFile)
		if err != nil {
			return err
		}
		cfg.parsedHostKeys = append(cfg.parsedHostKeys, signer)
	}
	return nil
}

func (cfg *config) setupSSHConfig() error {
	sshConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			RekeyThreshold: cfg.SSHProto.RekeyThreshold,
			KeyExchanges:   cfg.SSHProto.KeyExchanges,
			Ciphers:        cfg.SSHProto.Ciphers,
			MACs:           cfg.SSHProto.MACs,
		},
		NoClientAuth:                cfg.Auth.NoAuth,
		MaxAuthTries:                cfg.Auth.MaxTries,
		PasswordCallback:            cfg.getPasswordCallback(),
		PublicKeyCallback:           cfg.getPublicKeyCallback(),
		KeyboardInteractiveCallback: cfg.getKeyboardInteractiveCallback(),
		AuthLogCallback:             cfg.getAuthLogCallback(),
		ServerVersion:               cfg.SSHProto.Version,
		BannerCallback:              cfg.getBannerCallback(),
	}
	if err := cfg.parseHostKeys(); err != nil {
		return err
	}
	for _, key := range cfg.parsedHostKeys {
		sshConfig.AddHostKey(key)
	}
	cfg.sshConfig = sshConfig
	return nil
}

func (cfg *config) setupLogging() error {
	var logFile io.WriteCloser
	if cfg.Logging.File != "" {
		var err error
		logFile, err = os.OpenFile(cfg.Logging.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
	}
	if logFile == nil {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(logFile)
	}
	if cfg.logFileHandle != nil {
		cfg.logFileHandle.Close()
	}
	cfg.logFileHandle = logFile
	if !cfg.Logging.JSON && cfg.Logging.Timestamps {
		log.SetFlags(log.LstdFlags)
	} else {
		log.SetFlags(0)
	}
	return nil
}

func (cfg *config) load(configString string, dataDir string) error {
	*cfg = config{}

	cfg.setDefaults()

	if err := yaml.UnmarshalStrict([]byte(configString), cfg); err != nil {
		return err
	}

	if cfg.Server.TCPIPServices == nil {
		cfg.Server.TCPIPServices = defaultTCPIPServices
	}

	for _, service := range cfg.Server.TCPIPServices {
		if _, ok := servers[service]; !ok {
			return fmt.Errorf("unknown service %q", service)
		}
	}

	if len(cfg.Server.HostKeys) == 0 {
		infoLogger.Printf("No host keys configured, using keys at %q", dataDir)
		if err := cfg.setDefaultHostKeys(dataDir, []keySignature{rsa_key, ecdsa_key, ed25519_key}); err != nil {
			return err
		}
	}

	if err := cfg.setupSSHConfig(); err != nil {
		return err
	}
	if err := cfg.setupLogging(); err != nil {
		return err
	}

	return nil
}
