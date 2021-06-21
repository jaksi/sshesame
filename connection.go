package main

import (
	"encoding/base64"
	"log"
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type connMetadata struct {
	ssh.ConnMetadata
}

func (metadata connMetadata) getLogEntry() *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"client_version": string(metadata.ClientVersion()),
		"session_id":     base64.RawStdEncoding.EncodeToString(metadata.SessionID()),
		"user":           metadata.User(),
		"remote_address": metadata.RemoteAddr().String(),
	})
}

type channelMetadata struct {
	connMetadata
	channelID   int
	channelType string
}

func (metadata channelMetadata) getLogEntry() *logrus.Entry {
	return metadata.connMetadata.getLogEntry().WithFields(logrus.Fields{
		"channel_id":   metadata.channelID,
		"channel_type": metadata.channelType,
	})
}

var channelHandlers = map[string]func(newChannel ssh.NewChannel, metadata channelMetadata) error{
	"session":      handleSessionChannel,
	"direct-tcpip": handleDirectTCPIPChannel,
}

func handleConnection(conn net.Conn, cfg *config) {
	defer conn.Close()
	logrus.WithField("remote_address", conn.RemoteAddr().String()).Infoln("Connection accepted")
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

	go func() {
		for request := range requests {
			if err := handleGlobalRequest(request, metadata); err != nil {
				log.Println("Failed to handle global request:", err)
				serverConn.Close()
			}
		}
	}()

	channelID := 0
	for newChannel := range newChannels {
		channelType := newChannel.ChannelType()
		handler := channelHandlers[channelType]
		if handler == nil {
			log.Println("Unsupported channel type", channelType)
			if err := newChannel.Reject(ssh.ConnectionFailed, "open failed"); err != nil {
				log.Println("Failed to reject channel:", err)
				break
			}
			continue
		}
		go func() {
			if err := handler(newChannel, channelMetadata{metadata, channelID, channelType}); err != nil {
				log.Println("Failed to handle new channel:", err)
				serverConn.Close()
			}
		}()
		channelID++
	}
}
