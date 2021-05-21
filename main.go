package main

import (
	"log"
	"net"
	"os"

	"github.com/sirupsen/logrus"
)

func main() {
	cfg, err := getConfig()
	if err != nil {
		log.Fatalln("Failed to get config:", err)
	}

	sshServerConfig := cfg.createSSHServerConfig()

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		log.Fatalln("Failed to listen for connections:", err)
	}
	defer listener.Close()

	logrus.SetOutput(os.Stdout)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
			continue
		}
		logrus.WithFields(logrus.Fields{"remote_address": conn.RemoteAddr().String()}).Infoln("Connection accepted")
		go handleConnection(conn, sshServerConfig)
	}
}
