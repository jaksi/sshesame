package main

import (
	"net"

	"golang.org/x/crypto/ssh"
)

type connContext struct {
	ssh.ConnMetadata
	cfg            *config
	noMoreSessions bool
}

type channelContext struct {
	connContext
	channelID int
}

var channelHandlers = map[string]func(newChannel ssh.NewChannel, context channelContext) error{
	"session":      handleSessionChannel,
	"direct-tcpip": handleDirectTCPIPChannel,
}

func handleConnection(conn net.Conn, cfg *config) {
	serverConn, newChannels, requests, err := ssh.NewServerConn(conn, cfg.sshConfig)
	if err != nil {
		warningLogger.Printf("Failed to establish SSH connection: %v", err)
		conn.Close()
		return
	}
	channelsDone := []chan interface{}{}
	context := connContext{ConnMetadata: serverConn, cfg: cfg}
	defer func() {
		serverConn.Close()
		for _, channelDone := range channelsDone {
			<-channelDone
		}
		context.logEvent(connectionCloseLog{})
	}()

	context.logEvent(connectionLog{
		ClientVersion: string(serverConn.ClientVersion()),
	})

	if _, _, err := serverConn.SendRequest("hostkeys-00@openssh.com", false, createHostkeysRequestPayload(cfg.parsedHostKeys)); err != nil {
		warningLogger.Printf("Failed to send hostkeys-00@openssh.com request: %v", err)
		return
	}

	channelID := 0
loop:
	for requests != nil && newChannels != nil {
		select {
		case request, ok := <-requests:
			if !ok {
				requests = nil
				continue
			}
			if err := handleGlobalRequest(request, &context); err != nil {
				warningLogger.Printf("Failed to handle global request: %v", err)
				break loop
			}
		case newChannel, ok := <-newChannels:
			if !ok {
				newChannels = nil
				continue
			}
			warningLogger.Printf("Servin new channel %v: %v\n", newChannel.ChannelType(), context.noMoreSessions)
			channelType := newChannel.ChannelType()
			handler := channelHandlers[channelType]
			if handler == nil {
				warningLogger.Printf("Unsupported channel type %v", channelType)
				if err := newChannel.Reject(ssh.ConnectionFailed, "open failed"); err != nil {
					warningLogger.Printf("Failed to reject channel: %v", err)
					break loop
				}
				continue
			}
			go func(context channelContext) {
				channelDone := make(chan interface{})
				channelsDone = append(channelsDone, channelDone)
				defer func() { channelDone <- nil }()
				if err := handler(newChannel, context); err != nil {
					warningLogger.Printf("Failed to handle new channel: %v", err)
					serverConn.Close()
				}
			}(channelContext{context, channelID})
			channelID++
		}
	}
}
