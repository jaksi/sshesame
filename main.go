package main

import (
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
	for _, hostKey := range config.hostKeys {
		sshServerConfig.AddHostKey(hostKey)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:2022")
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
