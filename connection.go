package main

import (
	"log"
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func handleConnection(conn net.Conn, sshServerConfig *ssh.ServerConfig, hostKeys []ssh.Signer) {
	logrus.WithField("remote_address", conn.RemoteAddr().String()).Infoln("Connection accepted")
	defer conn.Close()
	defer logrus.WithField("remote_address", conn.RemoteAddr().String()).Infoln("Connection closed")
	serverConn, newChannels, requests, err := ssh.NewServerConn(conn, sshServerConfig)
	if err != nil {
		log.Println("Failed to establish SSH connection:", err)
		return
	}
	defer serverConn.Close()

	getLogEntry(serverConn).Infoln("SSH connection established")
	defer getLogEntry(serverConn).Infoln("SSH connection closed")

	hostkeysData := make([]string, 0)
	for _, hostKey := range hostKeys {
		hostkeysData = append(hostkeysData, string(hostKey.PublicKey().Marshal()))
	}
	if _, _, err := serverConn.SendRequest("hostkeys-00@openssh.com", false, marshalStrings(hostkeysData)); err != nil {
		log.Println("Failed to send hostkeys-00@openssh.com request:", err)
		return
	}

	go handleGlobalRequests(requests, serverConn)

	channelID := 0
	for newChannel := range newChannels {
		go handleNewChannel(newChannel, channelMetadata{conn: serverConn, channelID: channelID})
		channelID++
	}
}
