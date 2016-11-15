package channel

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/jaksi/sshesame/request"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"net"
	"strconv"
)

// RFC 4254
type x11 struct {
	SourceAddress string
	SourcePort    uint32
}

func (payload x11) String() string {
	return net.JoinHostPort(payload.SourceAddress, strconv.Itoa(int(payload.SourcePort)))
}

type tcpip struct {
	DestinationAddress string
	DestinationPort    uint32
	SourceAddress      string
	SourcePort         uint32
}

func (payload tcpip) String() string {
	return fmt.Sprintf("%v -> %v",
		net.JoinHostPort(payload.SourceAddress, strconv.Itoa(int(payload.SourcePort))),
		net.JoinHostPort(payload.DestinationAddress, strconv.Itoa(int(payload.DestinationPort))))
}

func Handle(remoteAddr net.Addr, newChannel ssh.NewChannel) {
	var payload interface{} = newChannel.ExtraData()
	switch newChannel.ChannelType() {
	case "x11":
		parsedPayload := x11{}
		err := ssh.Unmarshal(newChannel.ExtraData(), &parsedPayload)
		if err != nil {
			log.Warning("Failed to parse payload:", err.Error())
			break
		}
		payload = parsedPayload
	case "forwarded-tcpip":
		// Server initiated forwarding
		fallthrough
	case "direct-tcpip":
		// Client initiated forwarding
		parsedPayload := tcpip{}
		err := ssh.Unmarshal(newChannel.ExtraData(), &parsedPayload)
		if err != nil {
			log.Warning("Failed to parse payload:", err.Error())
			break
		}
		payload = parsedPayload
	}
	log.WithFields(log.Fields{
		"client":  remoteAddr,
		"channel": newChannel.ChannelType(),
		"payload": payload,
	}).Info("Channel requested")
	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		log.Warning("Failed to accept channel:", err.Error())
		return
	}
	defer channel.Close()
	go request.Handle(remoteAddr, newChannel.ChannelType(), channelRequests)
	if newChannel.ChannelType() == "session" {
		terminal := terminal.NewTerminal(channel, "$ ")
		for {
			line, err := terminal.ReadLine()
			if err != nil {
				if err == io.EOF {
					log.WithFields(log.Fields{
						"client":  remoteAddr,
						"channel": newChannel.ChannelType(),
					}).Info("Terminal closed")
					request.SendExitStatus(channel)
				} else {
					log.Warning("Failed to read from terminal:", err.Error())
				}
				break
			}
			log.WithFields(log.Fields{
				"client":  remoteAddr,
				"channel": newChannel.ChannelType(),
				"line":    line,
			}).Info("Channel input received")
		}
	} else {
		data := make([]byte, 256)
		for {
			length, err := channel.Read(data)
			if err != nil {
				if err == io.EOF {
					log.WithFields(log.Fields{
						"client":  remoteAddr,
						"channel": newChannel.ChannelType(),
					}).Info("Channel closed")
				} else {
					log.Warning("Failed to read from channel:", err.Error())
				}
				break
			}
			log.WithFields(log.Fields{
				"client":  remoteAddr,
				"channel": newChannel.ChannelType(),
				"data":    string(data[:length]),
			}).Info("Channel input received")
		}
	}
}
