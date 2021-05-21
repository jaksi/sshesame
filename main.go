package main

import (
	"io/ioutil"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func main() {
	config, err := getConfig()
	if err != nil {
		log.Fatalln("Failed to get config:", err)
	}

	sshServerConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	for _, hostKeyFileName := range config.hostKeys {
		hostKeyBytes, err := ioutil.ReadFile(hostKeyFileName)
		if err != nil {
			log.Fatalln("Failed to read host key", hostKeyFileName, ":", err)
		}
		signer, err := ssh.ParsePrivateKey(hostKeyBytes)
		if err != nil {
			log.Fatalln("Failed to parse host key", hostKeyFileName, ":", err)
		}
		sshServerConfig.AddHostKey(signer)
	}

	listener, err := net.Listen("tcp", config.listenAddress)
	if err != nil {
		log.Fatalln("Failed to listen for connections:", err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
			continue
		}
		go handleConnection(conn, sshServerConfig)
	}
}
