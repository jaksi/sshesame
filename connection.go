package main

import (
	"net"

	"golang.org/x/crypto/ssh"
)

type connMetadata struct {
	ssh.ConnMetadata
	cfg *config
}

type channelMetadata struct {
	connMetadata
	channelID int
}

var channelHandlers = map[string]func(newChannel ssh.NewChannel, metadata channelMetadata) error{
	"session":      handleSessionChannel,
	"direct-tcpip": handleDirectTCPIPChannel,
}

func handleConnection(conn net.Conn, cfg *config) {
	defer conn.Close()
	serverConn, newChannels, requests, err := ssh.NewServerConn(conn, cfg.sshConfig)
	if err != nil {
		warningLogger.Printf("Failed to establish SSH connection: %v", err)
		return
	}
	channelsDone := []chan interface{}{}
	metadata := connMetadata{serverConn, cfg}
	defer func() {
		serverConn.Close()
		for _, channel := range channelsDone {
			<-channel
		}
		metadata.logEvent(connectionCloseLog{})
	}()

	metadata.logEvent(connectionLog{
		ClientVersion: string(serverConn.ClientVersion()),
	})

	if _, _, err := serverConn.SendRequest("hostkeys-00@openssh.com", false, createHostkeysRequestPayload(cfg.parsedHostKeys)); err != nil {
		warningLogger.Printf("Failed to send hostkeys-00@openssh.com request: %v", err)
		return
	}

	go func() {
		for request := range requests {
			if err := handleGlobalRequest(request, metadata); err != nil {
				warningLogger.Printf("Failed to handle global request: %v", err)
				serverConn.Close()
			}
		}
	}()

	channelID := 0
	for newChannel := range newChannels {
		channelType := newChannel.ChannelType()
		handler := channelHandlers[channelType]
		if handler == nil {
			warningLogger.Printf("Unsupported channel type %v", channelType)
			if err := newChannel.Reject(ssh.ConnectionFailed, "open failed"); err != nil {
				warningLogger.Printf("Failed to reject channel: %v", err)
				break
			}
			continue
		}
		go func(channelID int) {
			channelDone := make(chan interface{})
			channelsDone = append(channelsDone, channelDone)
			defer func() { channelDone <- nil }()
			if err := handler(newChannel, channelMetadata{metadata, channelID}); err != nil {
				warningLogger.Printf("Failed to handle new channel: %v", err)
				serverConn.Close()
			}
		}(channelID)
		channelID++
	}
}
