package main

import (
	"log"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func handleConnection(conn net.Conn, sshServerConfig *ssh.ServerConfig) {
	defer conn.Close()
	defer logrus.WithField("remote_address", conn.RemoteAddr().String()).Infoln("Connection closed")
	serverConn, newChannels, requests, err := ssh.NewServerConn(conn, sshServerConfig)
	if err != nil {
		log.Println("Failed to establish SSH connection:", err)
		return
	}

	getLogEntry(serverConn).Infoln("SSH connection established")
	defer getLogEntry(serverConn).Infoln("SSH connection closed")

	if strings.HasPrefix(string(serverConn.ClientVersion()), "SSH-2.0-OpenSSH") && strings.HasPrefix(string(serverConn.ServerVersion()), "SSH-2.0-OpenSSH") {
		serverConn.SendRequest("hostkeys-00@openssh.com", false, ssh.Marshal(struct{ hostKeys []string }{}))
	}

	go handleGlobalRequests(requests, serverConn)

	channelID := 0
	for newChannel := range newChannels {
		go handleNewChannel(newChannel, channelMetadata{conn: serverConn, channelID: channelID})
		channelID++
	}
}
