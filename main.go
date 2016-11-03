package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net"
)

func main() {
	hostKey := flag.String("host_key", "", "a file containing a private key to use")
	listenAddress := flag.String("listen_address", "localhost", "the local address to listen on")
	port := flag.Uint("port", 2022, "the port number to listen on")
	flag.Parse()

	var key ssh.Signer
	var err error
	if *hostKey != "" {
		keyBytes, err := ioutil.ReadFile(*hostKey)
		if err != nil {
			log.Fatalln("Failed to read host key:", err.Error())
		}
		key, err = ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			log.Fatalln("Failed to parse host key:", err.Error())
		}
	} else {
		log.Println("WARNING: Generating a temporary private key. Consider creating one and passing it to -host_key")
		_, keyBytes, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatalln("Failed to generate temporary private key:", err.Error())
		}
		key, err = ssh.NewSignerFromSigner(keyBytes)
		if err != nil {
			log.Fatalln("Failed to parse generated private key:", err.Error())
		}
		log.Printf("SHA-256 fingerprint: %v\n", sha256.Sum256(key.PublicKey().Marshal()))
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
		log.Fatalln("Failed to listen:", err.Error())
	}
	log.Printf("Listen: %v\n", listener.Addr())
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err.Error())
			continue
		}
		log.Printf("Connection: client=%v\n", conn.RemoteAddr())
		go handleConn(serverConfig, conn)
	}
}

func handleConn(serverConfig *ssh.ServerConfig, conn net.Conn) {
	defer conn.Close()
	_, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		log.Println("Failed to establish SSH connection:", err.Error())
		return
	}
	log.Printf("Established SSH connection: client=%v\n", conn.RemoteAddr())
	go handleRequests(conn.RemoteAddr(), "global", requests)
	for newChannel := range channels {
		go handleNewChannel(conn.RemoteAddr(), newChannel)
	}
	log.Printf("Disconnect: client=%v\n", conn.RemoteAddr())
}
