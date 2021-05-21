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
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/adrg/xdg"
	"gopkg.in/yaml.v2"
)

type config struct {
	ListenAddress string
	HostKeys      []string
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
		if keyType == rsa_key {
			key, err = rsa.GenerateKey(rand.Reader, 3072)
		} else if keyType == ecdsa_key {
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		} else if keyType == ed25519_key {
			_, key, err = ed25519.GenerateKey(rand.Reader)
		} else {
			return errors.New("unsupported key type")
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

func getConfig() (*config, error) {
	result := &config{
		ListenAddress: "127.0.0.1:2022",
	}

	configFileName := flag.String("config", "", "config file")
	var configBytes []byte
	var err error
	if *configFileName == "" {
		configBytes, err = ioutil.ReadFile(path.Join(xdg.ConfigHome, "sshesame.yaml"))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		configBytes, err = ioutil.ReadFile(*configFileName)
		if err != nil {
			return nil, err
		}
	}
	if configBytes != nil {
		if err := yaml.UnmarshalStrict(configBytes, result); err != nil {
			return nil, err
		}
	}

	if len(result.HostKeys) == 0 {
		dataDir := path.Join(xdg.DataHome, "sshesame")
		log.Println("No host keys configured, using keys at", dataDir)

		for keyType, fileName := range map[hostKeyType]string{
			rsa_key:     "host_rsa_key",
			ecdsa_key:   "host_ecdsa_key",
			ed25519_key: "host_ed25519_key",
		} {
			keyFileName := path.Join(dataDir, fileName)
			if err := generateKey(keyFileName, keyType); err != nil {
				return nil, err
			}
			result.HostKeys = []string{keyFileName}
		}
	}

	return result, nil
}
