package main

import (
	"flag"
	"log"
	"net"
	"path"

	"github.com/adrg/xdg"
	"github.com/sirupsen/logrus"
)

func main() {
	configFileName := flag.String("config", "", "config file")
	flag.Parse()

	cfg, err := getConfig(*configFileName, path.Join(xdg.DataHome, "sshesame"))
	if err != nil {
		log.Fatalln("Failed to get config:", err)
	}

	sshServerConfig, err := cfg.createSSHServerConfig()
	if err != nil {
		log.Fatalln("Failed to create SSH server config:", err)
	}

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		log.Fatalln("Failed to listen for connections:", err)
	}
	defer listener.Close()

	log.Println("Listening on", listener.Addr())

	logFile, err := cfg.setupLogging()
	if err != nil {
		log.Fatalln("Failed to setup logging:", err)
	}
	if logFile != nil {
		defer logFile.Close()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
			continue
		}
		logrus.WithField("remote_address", conn.RemoteAddr().String()).Infoln("Connection accepted")
		go handleConnection(conn, sshServerConfig)
	}
}
