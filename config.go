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
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

type config struct {
	ListenAddress           string
	LogFile                 string
	JSONLogging             bool
	RekeyThreshold          uint64
	KeyExchanges            []string
	Ciphers                 []string
	MACs                    []string
	HostKeys                []string
	NoClientAuth            bool
	MaxAuthTries            int
	PasswordAuth            struct{ Enabled, Accepted bool }
	PublicKeyAuth           struct{ Enabled, Accepted bool }
	KeyboardInteractiveAuth struct {
		Enabled, Accepted bool
		Instruction       string
		Questions         []struct {
			Text string
			Echo bool
		}
	}
	ServerVersion string
	Banner        string

	parsedHostKeys []ssh.Signer
	sshConfig      *ssh.ServerConfig
	logFileHandle  *os.File
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
	cfg.PublicKeyAuth.Accepted = false
	return cfg
}

func (cfg *config) setDefaultHostKeys(dataDir string) error {
	for _, key := range []struct {
		keyType  hostKeyType
		filename string
	}{
		{keyType: rsa_key, filename: "host_rsa_key"},
		{keyType: ecdsa_key, filename: "host_ecdsa_key"},
		{keyType: ed25519_key, filename: "host_ed25519_key"},
	} {
		keyFileName := path.Join(dataDir, key.filename)
		if err := generateKey(keyFileName, key.keyType); err != nil {
			return err
		}
		cfg.HostKeys = append(cfg.HostKeys, keyFileName)
	}
	return nil
}

func (cfg *config) parseHostKeys() error {
	for _, key := range cfg.HostKeys {
		keyBytes, err := ioutil.ReadFile(key)
		if err != nil {
			return err
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
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
	if err := cfg.parseHostKeys(); err != nil {
		return err
	}
	for _, hostKey := range cfg.parsedHostKeys {
		sshConfig.AddHostKey(hostKey)
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

type hostKeyType int

const (
	rsa_key hostKeyType = iota
	ecdsa_key
	ed25519_key
)

func generateKey(keyFile string, keyType hostKeyType) error {
	if _, err := os.Stat(keyFile); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	log.Println("Host key", keyFile, "not found, generating it")
	if _, err := os.Stat(path.Dir(keyFile)); os.IsNotExist(err) {
		if err := os.MkdirAll(path.Dir(keyFile), 0755); err != nil {
			return err
		}
	}
	var key interface{}
	var err error
	switch keyType {
	case rsa_key:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case ecdsa_key:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ed25519_key:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		err = errors.New("unsupported key type")
	}
	if err != nil {
		return err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		return err
	}
	return nil
}

func getConfig(configFile string, dataDir string) (*config, error) {
	cfg := getDefaultConfig()

	var configBytes []byte
	var err error
	if configFile != "" {
		configBytes, err = ioutil.ReadFile(configFile)
		if err != nil {
			return nil, err
		}
	}
	if err := yaml.UnmarshalStrict(configBytes, cfg); err != nil {
		return nil, err
	}

	if len(cfg.HostKeys) == 0 {
		log.Println("No host keys configured, using keys at", dataDir)
		cfg.setDefaultHostKeys(dataDir)
	}

	if err := cfg.setupSSHConfig(); err != nil {
		return nil, err
	}
	if err := cfg.setupLogging(); err != nil {
		return nil, err
	}

	return cfg, nil
}
