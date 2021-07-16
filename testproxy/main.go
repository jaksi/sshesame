package main

import (
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

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

func handleChannel(clientChannel ssh.Channel, clientRequests <-chan *ssh.Request, upstreamChannel ssh.Channel, upstreamRequests <-chan *ssh.Request) {
	clientInputStream := streamReader(clientChannel)
	upstreamInputStream := streamReader(upstreamChannel)
	upstreamErrorStream := streamReader(upstreamChannel.Stderr())

	for clientInputStream != nil || clientRequests != nil || upstreamInputStream != nil || upstreamRequests != nil {
		select {
		case clientInput, ok := <-clientInputStream:
			if !ok {
				log.Printf("Client input stream closed")
				clientInputStream = nil
				upstreamChannel.CloseWrite()
				continue
			}
			log.Printf("Client data: %q", clientInput)
			if _, err := upstreamChannel.Write([]byte(clientInput)); err != nil {
				panic(err)
			}
		case clientRequest, ok := <-clientRequests:
			if !ok {
				log.Printf("Client channel closed")
				clientRequests = nil
				upstreamChannel.Close()
				continue
			}
			log.Printf("Client channel request: %s", clientRequest.Type)
			response, err := upstreamChannel.SendRequest(clientRequest.Type, clientRequest.WantReply, clientRequest.Payload)
			if err != nil {
				panic(err)
			}
			if clientRequest.WantReply {
				if err := clientRequest.Reply(response, nil); err != nil {
					panic(err)
				}
			}
		case upstreamInput, ok := <-upstreamInputStream:
			if !ok {
				log.Printf("Upstream input stream closed")
				upstreamInputStream = nil
				clientChannel.CloseWrite()
				continue
			}
			log.Printf("Upstream data: %q", upstreamInput)
			if _, err := clientChannel.Write([]byte(upstreamInput)); err != nil {
				panic(err)
			}
		case upstreamError, ok := <-upstreamErrorStream:
			if !ok {
				upstreamErrorStream = nil
				continue
			}
			log.Printf("Upstream error: %q", upstreamError)
			if _, err := clientChannel.Stderr().Write([]byte(upstreamError)); err != nil {
				panic(err)
			}
		case upstreamRequest, ok := <-upstreamRequests:
			if !ok {
				log.Printf("Upstream channel closed")
				upstreamRequests = nil
				clientChannel.Close()
				continue
			}
			log.Printf("Upstream channel request: %s", upstreamRequest.Type)
			response, err := clientChannel.SendRequest(upstreamRequest.Type, upstreamRequest.WantReply, upstreamRequest.Payload)
			if err != nil {
				panic(err)
			}
			if upstreamRequest.WantReply {
				if err := upstreamRequest.Reply(response, nil); err != nil {
					panic(err)
				}
			}
		}
	}
}

func handleConn(conn net.Conn, serverConfig *ssh.ServerConfig, upstreamAddress string, upstreamKey ssh.Signer) {
	defer conn.Close()

	clientSSHConn, clientNewChannels, clientRequests, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		panic(err)
	}
	defer clientSSHConn.Close()

	upstreamConn, err := net.Dial("tcp", upstreamAddress)
	if err != nil {
		panic(err)
	}
	defer upstreamConn.Close()

	upstreamSSHConn, upstreamNewChannels, upstreamRequests, err := ssh.NewClientConn(upstreamConn, upstreamAddress, &ssh.ClientConfig{
		User:            clientSSHConn.User(),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(upstreamKey),
		},
		ClientVersion: "SSH-2.0-OpenSSH_7.2",
	})
	if err != nil {
		panic(err)
	}
	defer upstreamSSHConn.Close()

	for clientNewChannels != nil || clientRequests != nil || upstreamNewChannels != nil || upstreamRequests != nil {
		select {
		case clientNewChannel, ok := <-clientNewChannels:
			if !ok {
				clientNewChannels = nil
				continue
			}
			log.Printf("New client channel: %s", clientNewChannel.ChannelType())
			upstreamChannel, upstreamChannelRequests, err := upstreamSSHConn.OpenChannel(clientNewChannel.ChannelType(), clientNewChannel.ExtraData())
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
			go handleChannel(clientChannel, clientChannelRequests, upstreamChannel, upstreamChannelRequests)
		case clientRequest, ok := <-clientRequests:
			if !ok {
				clientRequests = nil
				continue
			}
			log.Printf("Client request: %s", clientRequest.Type)
			if clientRequest.Type == "no-more-sessions@openssh.com" {
				continue
			}
			response, payload, err := upstreamSSHConn.SendRequest(clientRequest.Type, clientRequest.WantReply, clientRequest.Payload)
			if err != nil {
				panic(err)
			}
			if err := clientRequest.Reply(response, payload); err != nil {
				panic(err)
			}
		case upstreamNewChannel, ok := <-upstreamNewChannels:
			if !ok {
				upstreamNewChannels = nil
				continue
			}
			panic(upstreamNewChannel.ChannelType())
		case upstreamRequest, ok := <-upstreamRequests:
			if !ok {
				upstreamRequests = nil
				continue
			}
			log.Printf("Upstream request: %s", upstreamRequest.Type)
			response, payload, err := clientSSHConn.SendRequest(upstreamRequest.Type, upstreamRequest.WantReply, upstreamRequest.Payload)
			if err != nil {
				panic(err)
			}
			if err := upstreamRequest.Reply(response, payload); err != nil {
				panic(err)
			}
		}
	}
}

func main() {
	listenAddress := flag.String("listen_address", "127.0.0.1:2022", "listen address")
	hostKeyFile := flag.String("host_key_file", "", "host key file")
	upstreamAddress := flag.String("upstream_address", "127.0.0.1:22", "upstream address")
	upstreamKeyFile := flag.String("upstream_key_file", "", "upstream key file")
	flag.Parse()
	if *listenAddress == "" {
		panic("listen address is required")
	}
	if *hostKeyFile == "" {
		panic("host key file is required")
	}
	if *upstreamAddress == "" {
		panic("upstream address is required")
	}
	if *upstreamKeyFile == "" {
		panic("upstream key file is required")
	}

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

	upstreamKeyBytes, err := ioutil.ReadFile(*upstreamKeyFile)
	if err != nil {
		panic(err)
	}
	upstreamKey, err := ssh.ParsePrivateKey(upstreamKeyBytes)
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
		go handleConn(conn, serverConfig, *upstreamAddress, upstreamKey)
	}
}
