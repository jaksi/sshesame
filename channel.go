package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"net"
)

// RFC 4254
type x11 struct {
	SourceAddress string
	SourcePort    uint32
}
type tcpip struct {
	DestinationAddress string
	DestinationPort    uint32
	SourceAddress      string
	SourcePort         uint32
}

func handleNewChannel(remoteAddr net.Addr, newChannel ssh.NewChannel) {
	var payload string
	switch newChannel.ChannelType() {
	case "x11":
		parsedPayload := x11{}
		err := ssh.Unmarshal(newChannel.ExtraData(), &parsedPayload)
		if err != nil {
			log.Println("Failed to parse payload:", err.Error())
		}
		payload = fmt.Sprintf("%+v", parsedPayload)
	case "forwarded-tcpip":
		// Server initiated forwarding
		fallthrough
	case "direct-tcpip":
		// Client initiated forwarding
		parsedPayload := tcpip{}
		err := ssh.Unmarshal(newChannel.ExtraData(), &parsedPayload)
		if err != nil {
			log.Println("Failed to parse payload:", err.Error())
		}
		payload = fmt.Sprintf("%+v", parsedPayload)
	default:
		payload = fmt.Sprintf("%v", newChannel.ExtraData())
	}
	log.Printf("New channel: clinet=%v, type=%v, payload=%v\n", remoteAddr, newChannel.ChannelType(), payload)
	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		log.Println("Failed to accept channel:", err.Error())
		return
	}
	defer channel.Close()
	go handleRequests(remoteAddr, newChannel.ChannelType(), channelRequests)
	if newChannel.ChannelType() == "session" {
		terminal := terminal.NewTerminal(channel, "$ ")
		for {
			line, err := terminal.ReadLine()
			if err != nil {
				log.Println("Failed to read from terminal:", err.Error())
				break
			}
			log.Printf("Terminal: client=%v, channel=%v, line=%q\n", remoteAddr, newChannel.ChannelType(), line)
		}
	} else {
		data := make([]byte, 256)
		for {
			length, err := channel.Read(data)
			if err != nil {
				log.Println("Failed to read from channel:", err.Error())
				break
			}
			log.Printf("Channel input: client=%v, channel=%v, data=%q\n", remoteAddr, newChannel.ChannelType(), string(data[:length]))
		}
	}
}
