package main

import (
	"log"
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func handleConnection(conn net.Conn, cfg *config) {
	logrus.WithField("remote_address", conn.RemoteAddr().String()).Infoln("Connection accepted")
	defer conn.Close()
	defer logrus.WithField("remote_address", conn.RemoteAddr().String()).Infoln("Connection closed")
	serverConn, newChannels, requests, err := ssh.NewServerConn(conn, cfg.sshConfig)
	if err != nil {
		log.Println("Failed to establish SSH connection:", err)
		return
	}
	defer serverConn.Close()

	metadata := connMetadata{serverConn}
	metadata.getLogEntry().Infoln("SSH connection established")
	defer metadata.getLogEntry().Infoln("SSH connection closed")

	if _, _, err := serverConn.SendRequest("hostkeys-00@openssh.com", false, createHostkeysRequestPayload(cfg.parsedHostKeys)); err != nil {
		log.Println("Failed to send hostkeys-00@openssh.com request:", err)
		return
	}

	go handleGlobalRequests(requests, metadata)

	channelID := 0
	for newChannel := range newChannels {
		go handleNewChannel(newChannel, channelMetadata{metadata, channelID})
		channelID++
	}
}
