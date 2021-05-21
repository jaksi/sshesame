package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/adrg/xdg"
)

type config struct {
	listenAddress string
	hostKeys      []string
}

func getConfig() (*config, error) {
	result := &config{
		listenAddress: "127.0.0.1:2022",
	}

	if len(result.hostKeys) == 0 {
		dataDir := path.Join(xdg.DataHome, "sshesame")
		keyFileName := path.Join(dataDir, "host_rsa_key")
		if _, err := os.Stat(keyFileName); err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
			log.Println("Host key", keyFileName, "not found, generating it")
			if _, err := os.Stat(dataDir); os.IsNotExist(err) {
				if err := os.MkdirAll(dataDir, 0755); err != nil {
					return nil, err
				}
			}
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, err
			}
			if err := ioutil.WriteFile(keyFileName, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
				return nil, err
			}
			result.hostKeys = []string{keyFileName}
		}
	}

	return result, nil
}
