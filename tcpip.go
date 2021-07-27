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

	"golang.org/x/crypto/ssh"
)

type tcpipServer interface {
	serve(readWriter io.ReadWriter, input chan<- string)
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

func handleDirectTCPIPChannel(newChannel ssh.NewChannel, context channelContext) error {
	channelData := &tcpipChannelData{}
	if err := ssh.Unmarshal(newChannel.ExtraData(), channelData); err != nil {
		return err
	}
	server := servers[channelData.Port]
	if server == nil {
		warningLogger.Printf("Unsupported port %v", channelData.Port)
		return newChannel.Reject(ssh.ConnectionFailed, "Connection refused")
	}
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
	for i, line := range lines {
		var err error
		if i == len(lines)-1 {
			_, err = fmt.Fprintf(writer, "%d %s\r\n", reply.code, line)
		} else {
			_, err = fmt.Fprintf(writer, "%d-%s\r\n", reply.code, line)
		}
		if err != nil {
			return err
		}
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
	reply := smtpReply{
		code:    220,
		message: "localhost",
	}
	reader := bufio.NewReader(readWriter)
	var previousCommand string
	for {
		if err := server.writeReply(readWriter, reply); err != nil {
			warningLogger.Printf("Error writing reply: %v", err)
			return
		}
		if previousCommand == "QUIT" {
			return
		}
		if previousCommand == "DATA" {
			data, err := server.readData(readWriter)
			if err != nil {
				warningLogger.Printf("Error reading data: %v", err)
				return
			}
			input <- data
			reply = smtpReply{
				code:    250,
				message: "OK",
			}
			previousCommand = ""
			continue
		}
		command, err := server.readCommand(reader)
		if err != nil {
			warningLogger.Printf("Error reading command: %v", err)
			return
		}
		input <- command.String()
		previousCommand = command.command
		switch command.command {
		case "DATA":
			reply = smtpReply{
				code:    354,
				message: "Start mail input; end with <CRLF>.<CRLF>",
			}
		case "QUIT":
			reply = smtpReply{
				code:    221,
				message: "Bye",
			}
		default:
			reply = smtpReply{
				code:    250,
				message: "OK",
			}
		}
	}
}
