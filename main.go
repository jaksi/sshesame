package main

import (
	"flag"
	"log"
	"net"
	"path"

	"github.com/adrg/xdg"
)

func main() {
	configFile := flag.String("config", "", "config file")
	flag.Parse()

	cfg, err := getConfig(*configFile, path.Join(xdg.DataHome, "sshesame"))
	if err != nil {
		log.Fatalln("Failed to get config:", err)
	}

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		log.Fatalln("Failed to listen for connections:", err)
	}
	defer listener.Close()

	log.Println("Listening on", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
			continue
		}
		go handleConnection(conn, cfg)
	}
}
