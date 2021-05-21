package main

import (
	"log"
	"net"
)

func main() {
	cfg, err := getConfig()
	if err != nil {
		log.Fatalln("Failed to get config:", err)
	}

	sshServerConfig := cfg.createSshServerConfig()

	listener, err := net.Listen("tcp", cfg.ListenAddress)
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
