package main

import (
	"io"
	"log"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type channelMetadata struct {
	channelID int
	conn      ssh.ConnMetadata
}

func handleNewChannel(newChannel ssh.NewChannel, conn channelMetadata) {
	channel, _, err := newChannel.Accept()
	if err != nil {
		log.Println("Failed to accept new channel:", err)
	}

	conn.getLogEntry().WithFields(logrus.Fields{
		"channel_type":       newChannel.ChannelType(),
		"clannel_extra_data": newChannel.ExtraData(),
	}).Infoln("New channel accepted")
	if _, err := io.Copy(channel, channel); err != nil {
		log.Println("Failed to read from or write to channel:", err)
	}
}
