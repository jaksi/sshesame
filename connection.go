package main

import (
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func handleConnection(conn net.Conn, sshServerConfig *ssh.ServerConfig) {
	defer conn.Close()
	if _, _, _, err := ssh.NewServerConn(conn, sshServerConfig); err != nil {
		log.Println("Failed to establish SSH connection:", err)
		return
	}
}
