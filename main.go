package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net"
)

func main() {
	hostKey := flag.String("host_key", "host_key", "a file containing a private key to use")
	listenAddress := flag.String("listen_address", "localhost", "the local address to listen on")
	port := flag.Uint("port", 2022, "the port number to listen on")
	flag.Parse()

	keyBytes, err := ioutil.ReadFile(*hostKey)
	if err != nil {
		log.Fatalln(err.Error())
	}

	key, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		log.Fatalln(err.Error())
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			log.Printf("Login: client=%v, user=%q, password=%q\n", conn.RemoteAddr(), conn.User(), password)
			return nil, nil
		},
	}
	serverConfig.AddHostKey(key)

	listener, err := net.Listen("tcp", fmt.Sprintf("%v:%v", *listenAddress, *port))
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Printf("Listen: %v\n", listener.Addr())
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go handleConn(serverConfig, conn)
	}
}

func handleConn(serverConfig *ssh.ServerConfig, conn net.Conn) {
	defer conn.Close()
	_, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		log.Println(err.Error())
		return
	}
	go handleRequests(conn.RemoteAddr(), "global", requests)
	for newChannel := range channels {
		go handleNewChannel(conn.RemoteAddr(), newChannel)
	}
	log.Printf("Disconnect: client=%v\n", conn.RemoteAddr())
}
