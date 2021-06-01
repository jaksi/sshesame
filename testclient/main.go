package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

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
			log.Fatalln(err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			log.Fatalln(err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatalln(err)
	}
	defer conn.Close()
	sshClientConn, channels, requests, err := ssh.NewClientConn(conn, *addr, config)
	if err != nil {
		log.Fatalln(err)
	}
	defer sshClientConn.Close()
	go func() {
		for request := range requests {
			log.Printf("Global request received: %+v\n", request)
		}
	}()
	for channel := range channels {
		log.Printf("New channel requested: %+v\n", channel)
	}
}
