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
}

var servers = map[string]tcpipServer{
	"SMTP": smtpServer{},
	"HTTP": httpServer{},
	"POP3": pop3Server{},
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
	service := context.cfg.Server.TCPIPServices[channelData.Port]
	server := servers[service]
	if server == nil {
		tcpipChannelsMetric.WithLabelValues("unknown").Inc()
		warningLogger.Printf("Unsupported port %v", channelData.Port)
		return newChannel.Reject(ssh.ConnectionFailed, "Connection refused")
	}
	tcpipChannelsMetric.WithLabelValues(service).Inc()
	activeTCPIPChannelsMetric.WithLabelValues(service).Inc()
	defer activeTCPIPChannelsMetric.WithLabelValues(service).Dec()
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
			context.logEvent(debugChannelRequestLog{
				channelLog:  channelLog{ChannelID: context.channelID},
				RequestType: request.Type,
				WantReply:   request.WantReply,
				Payload:     string(request.Payload),
			})
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
		case "HELO":
		case "EHLO":
		case "MAIL":
		case "RCPT":
		case "RSET":
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

type pop3Server struct{}

type pop3Response struct {
	status    bool
	message   string
	multiline bool
}

func (pop3Server) writeResponse(writer io.Writer, reply pop3Response) error {
	lines := strings.Split(reply.message, "\n")
	if len(lines) > 1 && !reply.multiline {
		return fmt.Errorf("multiline response not allowed")
	}
	if reply.status {
		_, err := fmt.Fprintf(writer, "+OK %s\r\n", lines[0])
		if err != nil {
			return err
		}
	} else {
		_, err := fmt.Fprintf(writer, "-ERR %s\r\n", lines[0])
		if err != nil {
			return err
		}
	}
	if !reply.multiline {
		return nil
	}
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, ".") {
			fmt.Fprintf(writer, ".%s\r\n", line)
		} else {
			fmt.Fprintf(writer, "%s\r\n", line)
		}
	}
	if _, err := fmt.Fprintf(writer, ".\r\n"); err != nil {
		return err
	}
	return nil
}

type pop3Command struct {
	keyword string
	args    []string
}

func (command pop3Command) String() string {
	if len(command.args) == 0 {
		return command.keyword
	}
	return fmt.Sprintf("%s %s", command.keyword, strings.Join(command.args, " "))
}

func (pop3Server) readCommand(reader io.Reader) (pop3Command, error) {
	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil {
		return pop3Command{}, err
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return pop3Command{}, fmt.Errorf("empty command")
	}
	keyword := strings.ToUpper(fields[0])
	args := fields[1:]
	return pop3Command{keyword, args}, nil
}

func (server pop3Server) serve(readWriter io.ReadWriter, input chan<- string) {
	if err := server.writeResponse(readWriter, pop3Response{true, "localhost", false}); err != nil {
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
		var response pop3Response
		switch command.keyword {
		case "CAPA":
			response = pop3Response{true, "Capability list follows", true}
		case "LIST":
			if len(command.args) == 0 {
				response = pop3Response{true, "0 messages", true}
			} else {
				response = pop3Response{false, "No such message", false}
			}
		case "QUIT":
			response = pop3Response{true, "Bye!", false}
		default:
			warningLogger.Printf("Unknown POP3 command: %v", command)
			response = pop3Response{false, "unknown command", false}
		}
		if err := server.writeResponse(readWriter, response); err != nil {
			warningLogger.Printf("Error writing reply: %v", err)
			return
		}
		if command.keyword == "QUIT" {
			break
		}
	}
}
