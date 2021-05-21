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
	"golang.org/x/crypto/ssh"
)

type config struct {
	listenAddress string
	hostKeys      []ssh.Signer
}

func getConfig() (*config, error) {
	result := &config{
		listenAddress: "127.0.0.1:2022",
	}

	dataDir := path.Join(xdg.DataHome, "sshesame")
	keyFileName := path.Join(dataDir, "host_rsa_key")
	keyBytes, err := ioutil.ReadFile(keyFileName)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		log.Println("Host key", keyFileName, "not found, generating it.")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(dataDir); os.IsNotExist(err) {
			if err := os.MkdirAll(dataDir, 0755); err != nil {
				return nil, err
			}
		}
		if err := ioutil.WriteFile(keyFileName, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
			return nil, err
		}
		result.hostKeys = append(result.hostKeys, signer)
	} else {
		key, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
		result.hostKeys = append(result.hostKeys, key)
	}

	return result, nil
}
