package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/ssh"
)

type tcpipServer interface {
	serve(readWriter io.ReadWriter, input chan<- string)
	name() string
}

var servers = map[uint32]tcpipServer{
	25: smtpServer{},
	80: httpServer{},
}

type tcpipChannelData struct {
	Address           string
	Port              uint32
	OriginatorAddress string
	OriginatorPort    uint32
}

var (
	tcpipChannelsMetric = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sshesame_tcpip_channels_total",
		Help: "Total number of TCP/IP channels",
	}, []string{"service"})
	activeTCPIPChannelsMetric = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sshesame_active_tcpip_channels",
		Help: "Number of active TCP/IP channels",
	}, []string{"service"})
	tcpipChannelRequestsMetric = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sshesame_tcpip_channel_requests_total",
		Help: "Total number of TCP/IP channel requests",
	}, []string{"service"})
)

func handleDirectTCPIPChannel(newChannel ssh.NewChannel, context channelContext) error {
	channelData := &tcpipChannelData{}
	if err := ssh.Unmarshal(newChannel.ExtraData(), channelData); err != nil {
		return err
	}
	server := servers[channelData.Port]
	if server == nil {
		tcpipChannelsMetric.WithLabelValues("unknown").Inc()
		warningLogger.Printf("Unsupported port %v", channelData.Port)
		return newChannel.Reject(ssh.ConnectionFailed, "Connection refused")
	}
	tcpipChannelsMetric.WithLabelValues(server.name()).Inc()
	activeTCPIPChannelsMetric.WithLabelValues(server.name()).Inc()
	defer activeTCPIPChannelsMetric.WithLabelValues(server.name()).Dec()
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	context.logEvent(directTCPIPLog{
		channelLog: channelLog{
			ChannelID: context.channelID,
		},
		From: net.JoinHostPort(channelData.OriginatorAddress, strconv.Itoa(int(channelData.OriginatorPort))),
		To:   net.JoinHostPort(channelData.Address, strconv.Itoa(int(channelData.Port))),
	})
	defer context.logEvent(directTCPIPCloseLog{
		channelLog: channelLog{
			ChannelID: context.channelID,
		},
	})

	inputChan := make(chan string)
	go func() {
		defer close(inputChan)
		server.serve(channel, inputChan)
		if err := channel.CloseWrite(); err != nil {
			warningLogger.Printf("Error sending EOF to channel: %v", err)
			return
		}
		if err := channel.Close(); err != nil {
			warningLogger.Printf("Error closing channel: %v", err)
			return
		}
	}()

	for inputChan != nil || requests != nil {
		select {
		case input, ok := <-inputChan:
			if !ok {
				inputChan = nil
				continue
			}
			context.logEvent(directTCPIPInputLog{
				channelLog: channelLog{
					ChannelID: context.channelID,
				},
				Input: input,
			})
		case request, ok := <-requests:
			if !ok {
				requests = nil
				continue
			}
			tcpipChannelRequestsMetric.WithLabelValues("unknown").Inc()
			warningLogger.Printf("Unsupported direct-tcpip request type %v", request.Type)
			if request.WantReply {
				if err := request.Reply(false, nil); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

type httpServer struct{}

func (server httpServer) serve(readWriter io.ReadWriter, input chan<- string) {
	for {
		request, err := http.ReadRequest(bufio.NewReader(readWriter))
		if err != nil {
			if err != io.EOF {
				warningLogger.Printf("Error reading request: %v", err)
			}
			return
		}
		requestBytes, err := httputil.DumpRequest(request, true)
		if err != nil {
			warningLogger.Printf("Error dumping request: %v", err)
			return
		}
		input <- string(requestBytes)
		response := &http.Response{
			StatusCode: 404,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		responseBytes, err := httputil.DumpResponse(response, true)
		if err != nil {
			warningLogger.Printf("Error dumping response: %v", err)
			return
		}
		_, err = readWriter.Write(responseBytes)
		if err != nil {
			warningLogger.Printf("Error writing response: %v", err)
			return
		}
	}
}

func (httpServer) name() string {
	return "HTTP"
}

type smtpServer struct{}

type smtpReply struct {
	code    int
	message string
}

func (smtpServer) writeReply(writer io.Writer, reply smtpReply) error {
	lines := strings.Split(reply.message, "\n")
	for _, line := range lines[:len(lines)-1] {
		if _, err := fmt.Fprintf(writer, "%d-%s\r\n", reply.code, line); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "%d %s\r\n", reply.code, lines[len(lines)-1]); err != nil {
		return err
	}
	return nil
}

type smtpCommand struct {
	command string
	params  []string
}

func (command smtpCommand) String() string {
	if len(command.params) == 0 {
		return command.command
	}
	return fmt.Sprintf("%s %s", command.command, strings.Join(command.params, " "))
}

func (smtpServer) readCommand(reader io.Reader) (smtpCommand, error) {
	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil {
		return smtpCommand{}, err
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return smtpCommand{}, fmt.Errorf("empty command")
	}
	command := strings.ToUpper(fields[0])
	params := fields[1:]
	return smtpCommand{command, params}, nil
}

func (smtpServer) readData(reader io.Reader) (string, error) {
	bufioReader := bufio.NewReader(reader)
	data := bytes.Buffer{}
	crlf := false
	for {
		line, err := bufioReader.ReadString('\n')
		if err != nil {
			return "", err
		}
		data.WriteString(line)
		if crlf && line == ".\r\n" {
			return data.String(), nil
		}
		crlf = strings.HasSuffix(line, "\r\n")
	}
}

func (server smtpServer) serve(readWriter io.ReadWriter, input chan<- string) {
	if err := server.writeReply(readWriter, smtpReply{220, "localhost"}); err != nil {
		warningLogger.Printf("Error writing greeting: %v", err)
		return
	}
	for {
		command, err := server.readCommand(readWriter)
		if err != nil {
			warningLogger.Printf("Error reading command: %v", err)
			return
		}
		input <- command.String()
		reply := smtpReply{250, "OK"}
		switch command.command {
		case "EHLO":
			reply = smtpReply{220, "localhost"}
		case "MAIL":
		case "RCPT":
		case "DATA":
			if err := server.writeReply(readWriter, smtpReply{354, "Start mail input; end with <CRLF>.<CRLF>"}); err != nil {
				warningLogger.Printf("Error writing reply: %v", err)
				return
			}
			data, err := server.readData(readWriter)
			if err != nil {
				warningLogger.Printf("Error reading data: %v", err)
				return
			}
			input <- data
		case "QUIT":
			reply = smtpReply{221, "Bye!"}
		default:
			warningLogger.Printf("Unknown SMTP command: %v", command)
			reply = smtpReply{500, "unknown command"}
		}
		if err := server.writeReply(readWriter, reply); err != nil {
			warningLogger.Printf("Error writing reply: %v", err)
			return
		}
		if command.command == "QUIT" {
			break
		}
	}
}

func (smtpServer) name() string {
	return "SMTP"
}
