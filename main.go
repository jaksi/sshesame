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
	jsonLogging := flag.Bool("json_logging", false, "enable JSON logging")
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

	logrus.SetOutput(os.Stdout)
	if *jsonLogging {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	}

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
