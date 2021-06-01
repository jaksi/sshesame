package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func UnmarshalStrings(data []byte) ([]string, error) {
	result := make([]string, 0)
	for {
		if len(data) == 0 {
			return result, nil
		}
		if len(data) < 4 {
			return nil, errors.New("ran out of bytes")
		}
		size := binary.BigEndian.Uint32(data[:4])
		current := &struct{ Content string }{}
		if err := ssh.Unmarshal(data[:size+4], current); err != nil {
			return nil, err
		}
		result = append(result, current.Content)
		data = data[size+4:]
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:22", "")
	clientVersion := flag.String("client_version", "SSH-2.0-sshesame", "")
	user := flag.String("user", "root", "")
	password := flag.String("password", "", "")
	key := flag.String("key", "", "")
	flag.Parse()

	config := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            *user,
		ClientVersion:   *clientVersion,
	}
	if *password != "" {
		config.Auth = append(config.Auth, ssh.Password(*password))
	}
	if *key != "" {
		keyBytes, err := ioutil.ReadFile(*key)
		if err != nil {
			log.Panicln(err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			log.Panicln(err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Panicln(err)
	}
	defer conn.Close()

	sshClientConn, channels, requests, err := ssh.NewClientConn(conn, *addr, config)
	if err != nil {
		log.Panicln(err)
	}
	defer sshClientConn.Close()

	go func() {
		for request := range requests {
			log.Printf("Global request received: %+v\n", request)
			switch request.Type {
			case "hostkeys-00@openssh.com":
				hostKeys, err := UnmarshalStrings(request.Payload)
				if err != nil {
					log.Panicln(err)
				}
				for _, hostKey := range hostKeys {
					publicKey, err := ssh.ParsePublicKey([]byte(hostKey))
					if err != nil {
						log.Panicln(err)
					}
					log.Printf("Host key: %+v\n", publicKey)
				}
			}
		}
	}()

	for channel := range channels {
		log.Printf("New channel requested: %+v\n", channel)
	}
}
