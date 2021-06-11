package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type channelData fmt.Stringer

type channelDataParser func(data []byte) (channelData, error)

type tcpipChannelData struct {
	Address           string
	Port              uint32
	OriginatorAddress string
	OriginatorPort    uint32
}

func (data tcpipChannelData) String() string {
	return fmt.Sprintf("%v -> %v", net.JoinHostPort(data.OriginatorAddress, fmt.Sprint(data.OriginatorPort)), net.JoinHostPort(data.Address, fmt.Sprint(data.Port)))
}

var channelDataParsers = map[string]channelDataParser{
	"session": func(data []byte) (channelData, error) { return nil, nil },
	"direct-tcpip": func(data []byte) (channelData, error) {
		tcpipData := tcpipChannelData{}
		if err := ssh.Unmarshal(data, tcpipData); err != nil {
			return nil, err
		}
		return tcpipData, nil
	},
}

func handleNewChannel(newChannel ssh.NewChannel, metadata channelMetadata) {
	accept := true
	var data channelData
	if parser := channelDataParsers[newChannel.ChannelType()]; parser == nil {
		log.Println("Unsupported channel type", newChannel.ChannelType())
		accept = false
	} else {
		var err error
		data, err = parser(newChannel.ExtraData())
		if err != nil {
			log.Println("Failed to parse channel data:", err)
			accept = false
		}
	}
	var channelDataString string
	if data != nil {
		channelDataString = fmt.Sprint(data)
	} else {
		channelDataString = base64.RawStdEncoding.EncodeToString(newChannel.ExtraData())
	}
	metadata.getLogEntry().WithFields(logrus.Fields{
		"channel_type":       newChannel.ChannelType(),
		"channel_extra_data": channelDataString,
		"accepted":           accept,
	}).Infoln("New channel requested")

	if !accept {
		if err := newChannel.Reject(ssh.Prohibited, ""); err != nil {
			log.Println("Failed to reject new channel:", err)
		}
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Println("Failed to accept new channel:", err)
		return
	}
	defer channel.Close()
	defer metadata.getLogEntry().Infoln("Channel closed")

	go handleChannelRequests(requests, metadata)

	channelInput := make(chan string)
	defer close(channelInput)

	go func() {
		for input := range channelInput {
			metadata.getLogEntry().WithField("input", input).Infoln("Channel input received")
		}
	}()

	switch newChannel.ChannelType() {
	case "direct-tcpip":
		err = handleTCPIPChannel(channel, data.(*tcpipChannelData).Port, channelInput)
	case "session":
		err = handleSessionChannel(channel, channelInput)
	default:
		log.Println("Unsupported channel type", newChannel.ChannelType())
		return
	}
	if err != nil {
		log.Println("Failed to read from channel:", err)
		return
	}
}
