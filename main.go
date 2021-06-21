package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"path"

	"github.com/adrg/xdg"
)

func main() {
	configFile := flag.String("config", "", "config file")
	dataDir := flag.String("data_dir", path.Join(xdg.DataHome, "sshesame"), "data directory")
	flag.Parse()

	configString := ""
	if *configFile != "" {
		configBytes, err := ioutil.ReadFile(*configFile)
		if err != nil {
			log.Fatalln("Failed to read config file:", err)
		}
		configString = string(configBytes)
	}

	cfg, err := getConfig(configString, *dataDir, pkcs8fileKey{})
	if err != nil {
		log.Fatalln("Failed to get config:", err)
	}

	listener, err := net.Listen("tcp", cfg.Server.ListenAddress)
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
