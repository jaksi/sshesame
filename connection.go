package main

import (
	"net"
	"sync"

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
	var channels sync.WaitGroup
	context := connContext{ConnMetadata: serverConn, cfg: cfg}
	defer func() {
		serverConn.Close()
		channels.Wait()
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
	for requests != nil || newChannels != nil {
		select {
		case request, ok := <-requests:
			if !ok {
				requests = nil
				continue
			}
			context.logEvent(debugGlobalRequestLog{
				RequestType: request.Type,
				WantReply:   request.WantReply,
				Payload:     string(request.Payload),
			})
			if err := handleGlobalRequest(request, &context); err != nil {
				warningLogger.Printf("Failed to handle global request: %v", err)
				requests = nil
				continue
			}
		case newChannel, ok := <-newChannels:
			if !ok {
				newChannels = nil
				continue
			}
			context.logEvent(debugChannelLog{
				channelLog:  channelLog{ChannelID: channelID},
				ChannelType: newChannel.ChannelType(),
				ExtraData:   string(newChannel.ExtraData()),
			})
			channelType := newChannel.ChannelType()
			handler := channelHandlers[channelType]
			if handler == nil {
				warningLogger.Printf("Unsupported channel type %v", channelType)
				if err := newChannel.Reject(ssh.ConnectionFailed, "open failed"); err != nil {
					warningLogger.Printf("Failed to reject channel: %v", err)
					newChannels = nil
					continue
				}
				continue
			}
			channels.Add(1)
			go func(context channelContext) {
				defer channels.Done()
				if err := handler(newChannel, context); err != nil {
					warningLogger.Printf("Failed to handle new channel: %v", err)
					serverConn.Close()
				}
			}(channelContext{context, channelID})
			channelID++
		}
	}
}
