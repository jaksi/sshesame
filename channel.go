package main

import (
	"fmt"
	"io"
	"log"
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type channelMetadata struct {
	channelID int
	conn      ssh.ConnMetadata
}

type tcpipChannelData struct {
	Address           string
	Port              uint32
	OriginatorAddress string
	OriginatorPort    uint32
}

func (data tcpipChannelData) String() string {
	return fmt.Sprintf("%v -> %v", net.JoinHostPort(data.OriginatorAddress, fmt.Sprint(data.OriginatorPort)), net.JoinHostPort(data.Address, fmt.Sprint(data.Port)))
}

func handleNewChannel(newChannel ssh.NewChannel, conn channelMetadata) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Println("Failed to accept new channel:", err)
		return
	}
	defer channel.Close()

	var channelData interface{}
	switch newChannel.ChannelType() {
	case "session":
	case "direct-tcpip":
		channelData = new(tcpipChannelData)
	default:
		log.Println("Unsupported channel type", newChannel.ChannelType())
		return
	}
	channelDataString := ""
	if channelData != nil {
		if err := ssh.Unmarshal(newChannel.ExtraData(), channelData); err != nil {
			log.Println("Failed to parse channel data:", err)
			return
		}

		channelDataString = fmt.Sprint(channelData)
	}

	conn.getLogEntry().WithFields(logrus.Fields{
		"channel_type":       newChannel.ChannelType(),
		"clannel_extra_data": channelDataString,
	}).Infoln("New channel accepted")

	go handleChannelRequests(requests, conn)

	if _, err := io.Copy(channel, channel); err != nil {
		log.Println("Failed to read from or write to channel:", err)
		return
	}
}
