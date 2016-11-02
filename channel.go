package main

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"net"
)

func handleNewChannel(remoteAddr net.Addr, newChannel ssh.NewChannel) {
	log.Printf("New channel: clinet=%v, type=%v, payload=%v\n", remoteAddr, newChannel.ChannelType(), newChannel.ExtraData())
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
		data := make([]byte, 16)
		for {
			length, err := channel.Read(data)
			if err != nil {
				log.Println("Failed to read from channel:", err.Error())
				break
			}
			log.Printf("Channel input: client=%v, channel=%v, data=%v\n", remoteAddr, newChannel.ChannelType(), data[:length])
		}
	}
}
