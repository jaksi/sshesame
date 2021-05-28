package main

import (
	"flag"
	"log"
	"net"
	"os"

	"github.com/sirupsen/logrus"
)

func main() {
	configFileName := flag.String("config", "", "config file")
	flag.Parse()

	cfg, err := getConfig(*configFileName)
	if err != nil {
		log.Fatalln("Failed to get config:", err)
	}

	sshServerConfig := cfg.createSSHServerConfig()

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		log.Fatalln("Failed to listen for connections:", err)
	}
	defer listener.Close()

	log.Println("Listening on", listener.Addr())

	if cfg.LogFile != "" {
		logFile, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalln("Failed to open log file:", err)
		}
		defer logFile.Close()
		logrus.SetOutput(logFile)
	} else {
		logrus.SetOutput(os.Stdout)
	}
	if cfg.JSONLogging {
		logrus.SetFormatter(&logrus.JSONFormatter{})
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
