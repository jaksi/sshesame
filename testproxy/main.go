package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

type source int

const (
	client source = iota
	server
)

func (src source) String() string {
	switch src {
	case client:
		return "client"
	case server:
		return "server"
	default:
		return "unknown"
	}
}

func (src source) MarshalJSON() ([]byte, error) {
	return json.Marshal(src.String())
}

type channelLog struct {
	ChannelID int `json:"channel_id"`
}

type requestLog struct {
	Type      string `json:"type"`
	WantReply bool   `json:"want_reply"`
	Payload   string `json:"payload"`

	Accepted bool `json:"accepted"`
}

type logEntry interface {
	eventType() string
}

type globalRequestLog struct {
	requestLog

	Response string `json:"response"`
}

func (entry globalRequestLog) eventType() string {
	return "global_request"
}

type newChannelLog struct {
	Type      string `json:"type"`
	ExtraData string `json:"extra_data"`

	Accepted bool `json:"accepted"`
}

func (entry newChannelLog) eventType() string {
	return "new_channel"
}

type channelRequestLog struct {
	channelLog
	requestLog
}

func (entry channelRequestLog) eventType() string {
	return "channel_request"
}

type channelDataLog struct {
	channelLog
	Data string `json:"data"`
}

func (entry channelDataLog) eventType() string {
	return "channel_data"
}

type channelErrorLog struct {
	channelLog
	Data string `json:"data"`
}

func (entry channelErrorLog) eventType() string {
	return "channel_error"
}

type channelEOFLog struct {
	channelLog
}

func (entry channelEOFLog) eventType() string {
	return "channel_eof"
}

type channelCloseLog struct {
	channelLog
}

func (entry channelCloseLog) eventType() string {
	return "channel_close"
}

func logEvent(entry logEntry, src source) {
	jsonBytes, err := json.Marshal(struct {
		Source    string   `json:"source"`
		EventType string   `json:"event_type"`
		Event     logEntry `json:"event"`
	}{
		Source:    src.String(),
		EventType: entry.eventType(),
		Event:     entry,
	})
	if err != nil {
		panic(err)
	}
	log.Printf("%s", jsonBytes)
}

func streamReader(reader io.Reader) <-chan string {
	input := make(chan string)
	go func() {
		defer close(input)
		buffer := make([]byte, 256)
		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				input <- string(buffer[:n])
			}
			if err != nil {
				if err != io.EOF {
					panic(err)
				}
				return
			}
		}
	}()
	return input
}

func handleChannel(channelID int, clientChannel ssh.Channel, clientRequests <-chan *ssh.Request, serverChannel ssh.Channel, serverRequests <-chan *ssh.Request) {
	clientInputStream := streamReader(clientChannel)
	serverInputStream := streamReader(serverChannel)
	serverErrorStream := streamReader(serverChannel.Stderr())

	for clientInputStream != nil || clientRequests != nil || serverInputStream != nil || serverRequests != nil {
		select {
		case clientInput, ok := <-clientInputStream:
			if !ok {
				if serverInputStream != nil {
					logEvent(channelEOFLog{
						channelLog: channelLog{
							ChannelID: channelID,
						},
					}, client)
					if err := serverChannel.CloseWrite(); err != nil {
						panic(err)
					}
				}
				clientInputStream = nil
				continue
			}
			logEvent(channelDataLog{
				channelLog: channelLog{
					ChannelID: channelID,
				},
				Data: clientInput,
			}, client)
			if _, err := serverChannel.Write([]byte(clientInput)); err != nil {
				panic(err)
			}
		case clientRequest, ok := <-clientRequests:
			if !ok {
				if serverRequests != nil {
					logEvent(channelCloseLog{
						channelLog: channelLog{
							ChannelID: channelID,
						},
					}, client)
					if err := serverChannel.Close(); err != nil {
						panic(err)
					}
				}
				clientRequests = nil
				continue
			}
			accepted, err := serverChannel.SendRequest(clientRequest.Type, clientRequest.WantReply, clientRequest.Payload)
			if err != nil {
				panic(err)
			}
			logEvent(channelRequestLog{
				channelLog: channelLog{
					ChannelID: channelID,
				},
				requestLog: requestLog{
					Type:      clientRequest.Type,
					WantReply: clientRequest.WantReply,
					Payload:   base64.RawStdEncoding.EncodeToString(clientRequest.Payload),
					Accepted:  accepted,
				},
			}, client)
			if clientRequest.WantReply {
				if err := clientRequest.Reply(accepted, nil); err != nil {
					panic(err)
				}
			}
		case serverInput, ok := <-serverInputStream:
			if !ok {
				if clientInputStream != nil {
					logEvent(channelEOFLog{
						channelLog: channelLog{
							ChannelID: channelID,
						},
					}, server)
					if err := clientChannel.CloseWrite(); err != nil {
						panic(err)
					}
				}
				serverInputStream = nil
				continue
			}
			logEvent(channelDataLog{
				channelLog: channelLog{
					ChannelID: channelID,
				},
				Data: serverInput,
			}, server)
			if _, err := clientChannel.Write([]byte(serverInput)); err != nil {
				panic(err)
			}
		case serverError, ok := <-serverErrorStream:
			if !ok {
				serverErrorStream = nil
				continue
			}
			logEvent(channelErrorLog{
				channelLog: channelLog{
					ChannelID: channelID,
				},
				Data: serverError,
			}, server)
			if _, err := clientChannel.Stderr().Write([]byte(serverError)); err != nil {
				panic(err)
			}
		case serverRequest, ok := <-serverRequests:
			if !ok {
				if clientRequests != nil {
					logEvent(channelCloseLog{
						channelLog: channelLog{
							ChannelID: channelID,
						},
					}, server)
					if err := clientChannel.Close(); err != nil {
						panic(err)
					}
				}
				serverRequests = nil
				continue
			}
			accepted, err := clientChannel.SendRequest(serverRequest.Type, serverRequest.WantReply, serverRequest.Payload)
			if err != nil {
				panic(err)
			}
			logEvent(channelRequestLog{
				channelLog: channelLog{
					ChannelID: channelID,
				},
				requestLog: requestLog{
					Type:      serverRequest.Type,
					WantReply: serverRequest.WantReply,
					Payload:   base64.RawStdEncoding.EncodeToString(serverRequest.Payload),
					Accepted:  accepted,
				},
			}, server)
			if serverRequest.WantReply {
				if err := serverRequest.Reply(accepted, nil); err != nil {
					panic(err)
				}
			}
		}
	}
}

func handleConn(clientConn net.Conn, sshServerConfig *ssh.ServerConfig, serverAddress string, clientKey ssh.Signer) {
	defer clientConn.Close()

	clientSSHConn, clientNewChannels, clientRequests, err := ssh.NewServerConn(clientConn, sshServerConfig)
	if err != nil {
		panic(err)
	}
	defer clientSSHConn.Close()

	serverConn, err := net.Dial("tcp", serverAddress)
	if err != nil {
		panic(err)
	}
	defer serverConn.Close()

	serverSSHConn, serverNewChannels, serverRequests, err := ssh.NewClientConn(serverConn, serverAddress, &ssh.ClientConfig{
		User:            clientSSHConn.User(),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientKey),
		},
		ClientVersion: "SSH-2.0-OpenSSH_7.2",
	})
	if err != nil {
		panic(err)
	}
	defer serverSSHConn.Close()

	channelID := 0

	for clientNewChannels != nil || clientRequests != nil || serverNewChannels != nil || serverRequests != nil {
		select {
		case clientNewChannel, ok := <-clientNewChannels:
			if !ok {
				clientNewChannels = nil
				continue
			}
			serverChannel, serverChannelRequests, err := serverSSHConn.OpenChannel(clientNewChannel.ChannelType(), clientNewChannel.ExtraData())
			logEvent(newChannelLog{
				Type:      clientNewChannel.ChannelType(),
				ExtraData: base64.RawStdEncoding.EncodeToString(clientNewChannel.ExtraData()),
				Accepted:  err == nil,
			}, client)
			if err != nil {
				if err, ok := err.(*ssh.OpenChannelError); ok {
					if err := clientNewChannel.Reject(err.Reason, err.Message); err != nil {
						panic(err)
					}
					continue
				}
				panic(err)
			}
			clientChannel, clientChannelRequests, err := clientNewChannel.Accept()
			if err != nil {
				panic(err)
			}
			go handleChannel(channelID, clientChannel, clientChannelRequests, serverChannel, serverChannelRequests)
		case clientRequest, ok := <-clientRequests:
			if !ok {
				clientRequests = nil
				continue
			}
			if clientRequest.Type == "no-more-sessions@openssh.com" {
				logEvent(globalRequestLog{
					requestLog: requestLog{
						Type:      clientRequest.Type,
						WantReply: clientRequest.WantReply,
						Payload:   base64.RawStdEncoding.EncodeToString(clientRequest.Payload),
						Accepted:  clientRequest.WantReply,
					},
					Response: base64.RawStdEncoding.EncodeToString([]byte{}),
				}, client)
				continue
			}
			accepted, response, err := serverSSHConn.SendRequest(clientRequest.Type, clientRequest.WantReply, clientRequest.Payload)
			if err != nil {
				panic(err)
			}
			logEvent(globalRequestLog{
				requestLog: requestLog{
					Type:      clientRequest.Type,
					WantReply: clientRequest.WantReply,
					Payload:   base64.RawStdEncoding.EncodeToString(clientRequest.Payload),
					Accepted:  accepted,
				},
				Response: base64.RawStdEncoding.EncodeToString(response),
			}, client)
			if err := clientRequest.Reply(accepted, response); err != nil {
				panic(err)
			}
		case serverNewChannel, ok := <-serverNewChannels:
			if !ok {
				serverNewChannels = nil
				continue
			}
			panic(serverNewChannel.ChannelType())
		case serverRequest, ok := <-serverRequests:
			if !ok {
				serverRequests = nil
				continue
			}
			accepted, response, err := clientSSHConn.SendRequest(serverRequest.Type, serverRequest.WantReply, serverRequest.Payload)
			logEvent(globalRequestLog{
				requestLog: requestLog{
					Type:      serverRequest.Type,
					WantReply: serverRequest.WantReply,
					Payload:   base64.RawStdEncoding.EncodeToString(serverRequest.Payload),
					Accepted:  accepted,
				},
				Response: base64.RawStdEncoding.EncodeToString(response),
			}, server)
			if err != nil {
				panic(err)
			}
			if err := serverRequest.Reply(accepted, response); err != nil {
				panic(err)
			}
		}
		channelID++
	}
}

func main() {
	listenAddress := flag.String("listen_address", "127.0.0.1:2022", "listen address")
	hostKeyFile := flag.String("host_key_file", "", "host key file")
	serverAddress := flag.String("server_address", "127.0.0.1:22", "server address")
	clientKeyFile := flag.String("client_key_file", "", "client key file")
	flag.Parse()
	if *listenAddress == "" {
		panic("listen address is required")
	}
	if *hostKeyFile == "" {
		panic("host key file is required")
	}
	if *serverAddress == "" {
		panic("server address is required")
	}
	if *clientKeyFile == "" {
		panic("client key file is required")
	}

	log.SetFlags(0)

	serverConfig := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-2.0-OpenSSH_7.2",
	}
	hostKeyBytes, err := ioutil.ReadFile(*hostKeyFile)
	if err != nil {
		panic(err)
	}
	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		panic(err)
	}
	serverConfig.AddHostKey(hostKey)

	clientKeyBytes, err := ioutil.ReadFile(*clientKeyFile)
	if err != nil {
		panic(err)
	}
	clientKey, err := ssh.ParsePrivateKey(clientKeyBytes)
	if err != nil {
		panic(err)
	}

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go handleConn(conn, serverConfig, *serverAddress, clientKey)
	}
}
