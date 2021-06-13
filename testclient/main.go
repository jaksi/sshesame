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
		User: *user,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			log.Printf("host key\n  %#v\n  %#v\n  %#v\n", hostname, remote, key)
			return nil
		},
		BannerCallback: func(message string) error {
			log.Printf("banner\n  %#v\n", message)
			return nil
		},
		ClientVersion: *clientVersion,
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

	if _, _, err := sshClientConn.SendRequest("no-more-sessions@openssh.com", false, nil); err != nil {
		log.Panicln(err)
	}

	go func() {
		for request := range requests {
			log.Printf("global request\n  %#v\n  %#v\n  %#v\n", request.Type, request.WantReply, request.Payload)
		}
	}()

	go func() {
		for channel := range channels {
			log.Printf("channel\n  %#v\n", channel)
		}
	}()
}
