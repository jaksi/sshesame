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
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

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
}

func (cfg config) createSSHServerConfig() (*ssh.ServerConfig, error) {
	sshServerConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			RekeyThreshold: cfg.RekeyThreshold,
			KeyExchanges:   cfg.KeyExchanges,
			Ciphers:        cfg.Ciphers,
			MACs:           cfg.MACs,
		},
		NoClientAuth: cfg.NoClientAuth,
		MaxAuthTries: cfg.MaxAuthTries,
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			getLogEntry(conn).WithFields(logrus.Fields{
				"method":  method,
				"success": err == nil,
			}).Infoln("Client attempted to authenticate")
		},
		ServerVersion: cfg.ServerVersion,
	}
	if cfg.PasswordAuth.Enabled {
		sshServerConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			getLogEntry(conn).WithFields(logrus.Fields{
				"password": string(password),
				"success":  cfg.PasswordAuth.Accepted,
			}).Infoln("Password authentication attempted")
			if !cfg.PasswordAuth.Accepted {
				return nil, errors.New("")
			}
			return nil, nil
		}
	}
	if cfg.PublicKeyAuth.Enabled {
		sshServerConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			getLogEntry(conn).WithFields(logrus.Fields{
				"public_key_fingerprint": ssh.FingerprintSHA256(key),
				"success":                cfg.PublicKeyAuth.Accepted,
			}).Infoln("Public key authentication attempted")
			if !cfg.PublicKeyAuth.Accepted {
				return nil, errors.New("")
			}
			return nil, nil
		}
	}
	if cfg.KeyboardInteractiveAuth.Enabled {
		sshServerConfig.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			var questions []string
			var echos []bool
			for _, question := range cfg.KeyboardInteractiveAuth.Questions {
				questions = append(questions, question.Text)
				echos = append(echos, question.Echo)
			}
			answers, err := client(conn.User(), cfg.KeyboardInteractiveAuth.Instruction, questions, echos)
			if err != nil {
				log.Println("Failed to process keyboard interactive authentication:", err)
				return nil, errors.New("")
			}
			getLogEntry(conn).WithFields(logrus.Fields{
				"answers": strings.Join(answers, ", "),
				"success": cfg.KeyboardInteractiveAuth.Accepted,
			}).Infoln("Keyboard interactive authentication attempted")
			if !cfg.KeyboardInteractiveAuth.Accepted {
				return nil, errors.New("")
			}
			return nil, nil
		}
	}
	if cfg.Banner != "" {
		sshServerConfig.BannerCallback = func(conn ssh.ConnMetadata) string { return cfg.Banner }
	}
	for _, hostKeyFileName := range cfg.HostKeys {
		hostKeyBytes, err := ioutil.ReadFile(hostKeyFileName)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(hostKeyBytes)
		if err != nil {
			return nil, err
		}
		sshServerConfig.AddHostKey(signer)
	}
	return sshServerConfig, nil
}

func (cfg config) setupLogging() (*os.File, error) {
	var result *os.File
	if cfg.LogFile != "" {
		logFile, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		defer logFile.Close()
		logrus.SetOutput(logFile)
		result = logFile
	} else {
		logrus.SetOutput(os.Stdout)
	}
	if cfg.JSONLogging {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{})
	}
	return result, nil
}

type hostKeyType int

const (
	rsa_key hostKeyType = iota
	ecdsa_key
	ed25519_key
)

func generateKey(fileName string, keyType hostKeyType) error {
	if _, err := os.Stat(fileName); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		log.Println("Host key", fileName, "not found, generating it")
		if _, err := os.Stat(path.Dir(fileName)); os.IsNotExist(err) {
			if err := os.MkdirAll(path.Dir(fileName), 0755); err != nil {
				return err
			}
		}
		var key interface{}
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
		if err := ioutil.WriteFile(fileName, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
			return err
		}
	}
	return nil
}

func getConfig(fileName string, dataDir string) (*config, error) {
	result := &config{
		ListenAddress: "127.0.0.1:2022",
		ServerVersion: "SSH-2.0-sshesame",
		Banner:        "This is an SSH honeypot. Everything is logged and monitored.\n",
	}
	result.PasswordAuth.Enabled = true
	result.PasswordAuth.Accepted = true
	result.PublicKeyAuth.Enabled = true
	result.PublicKeyAuth.Accepted = false

	var configBytes []byte
	var err error
	if fileName != "" {
		configBytes, err = ioutil.ReadFile(fileName)
		if err != nil {
			return nil, err
		}
	}
	if err := yaml.UnmarshalStrict(configBytes, result); err != nil {
		return nil, err
	}
	if result.Banner != "" && !strings.HasSuffix(result.Banner, "\n") {
		result.Banner = fmt.Sprintf("%v\n", result.Banner)
	}
	result.Banner = strings.ReplaceAll(result.Banner, "\n", "\r\n")

	if len(result.HostKeys) == 0 {
		log.Println("No host keys configured, using keys at", dataDir)

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
				return nil, err
			}
			result.HostKeys = append(result.HostKeys, keyFileName)
		}
	}

	return result, nil
}
