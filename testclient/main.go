package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshChannel struct {
	ssh.Channel
	name string
}

func sendGlobalRequset(conn ssh.Conn, name string, wantReply bool, payload []byte) {
	time.Sleep(500 * time.Millisecond)
	accepted, response, err := conn.SendRequest(name, wantReply, payload)
	fmt.Printf(">global request %v\n  %#v\n  %#v\n", name, accepted, response)
	if err != nil {
		panic(err)
	}
}

func openChannel(conn ssh.Conn, name string, data []byte, success bool) *sshChannel {
	time.Sleep(500 * time.Millisecond)
	channel, requests, err := conn.OpenChannel(name, data)
	fmt.Printf(">channel %v\n  %#v\n", name, err)
	if success {
		if err != nil {
			panic(err)
		}
	} else {
		if _, ok := err.(*ssh.OpenChannelError); !ok {
			panic(err)
		}
		return nil
	}
	if err != nil {
		if success {
			panic(err)
		} else {
			return nil
		}
	}
	go func() {
		for request := range requests {
			fmt.Printf("<channel %v request\n  %#v\n  %#v\n  %#v\n", name, request.Type, request.WantReply, request.Payload)
			if request.WantReply {
				panic("WantReply")
			}
		}
		time.Sleep(100 * time.Millisecond)
		fmt.Printf("<close channel %v requests\n", name)
	}()
	go func() {
		scanner := bufio.NewScanner(channel)
		for scanner.Scan() {
			fmt.Printf("<channel %v stdout\n  %#v\n", name, scanner.Text())
		}
		time.Sleep(100 * time.Millisecond)
		fmt.Printf("<close channel %v stdout\n", name)
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}()
	go func() {
		scanner := bufio.NewScanner(channel.Stderr())
		for scanner.Scan() {
			fmt.Printf("<channel %v stderr\n  %#v\n", name, scanner.Text())
		}
		time.Sleep(100 * time.Millisecond)
		fmt.Printf("<close channel %v stderr\n", name)
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}()
	return &sshChannel{channel, name}
}

func (channel *sshChannel) sendRequset(name string, wantReply bool, payload []byte) {
	time.Sleep(500 * time.Millisecond)
	accepted, err := channel.SendRequest(name, wantReply, payload)
	fmt.Printf(">channel %v request %v\n  %#v\n", channel.name, name, accepted)
	if err != nil {
		panic(err)
	}
}

func (channel *sshChannel) write(data string, close bool) {
	time.Sleep(500 * time.Millisecond)
	_, err := channel.Write([]byte(data))
	fmt.Printf(">channel %v data\n  %#v\n", channel.name, data)
	if err != nil {
		panic(err)
	}
	if close {
		err = channel.CloseWrite()
		fmt.Printf(">closewrite channel %v\n", channel.name)
		if err != nil {
			panic(err)
		}
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:22", "")
	clientVersion := flag.String("client_version", "SSH-2.0-sshesame", "")
	user := flag.String("user", "root", "")
	password := flag.String("password", "", "")
	key := flag.String("key", "", "")
	flag.Parse()

	config := &ssh.ClientConfig{
		User: *user,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fmt.Printf("<host key\n  %#v\n", key)
			return nil
		},
		BannerCallback: func(message string) error {
			fmt.Printf("<banner\n  %#v\n", message)
			return nil
		},
		ClientVersion: *clientVersion,
	}
	if *password != "" {
		config.Auth = append(config.Auth, ssh.Password(*password))
	}
	if *key != "" {
		keyBytes, err := ioutil.ReadFile(*key)
		if err != nil {
			panic(err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			panic(err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	sshClientConn, channels, requests, err := ssh.NewClientConn(conn, *addr, config)
	if err != nil {
		panic(err)
	}
	defer sshClientConn.Close()
	fmt.Printf(">connect\n  %#v\n", string(sshClientConn.ServerVersion()))

	go func() {
		for request := range requests {
			fmt.Printf("<global request\n  %#v\n  %#v\n  %#v\n", request.Type, request.WantReply, request.Payload)
			if request.WantReply {
				panic("WantReply")
			}
		}
		time.Sleep(100 * time.Millisecond)
		fmt.Printf("<close global requests\n")
	}()

	go func() {
		for channel := range channels {
			panic(channel)
		}
		time.Sleep(100 * time.Millisecond)
		fmt.Printf("<close channels\n")
	}()

	sendGlobalRequset(sshClientConn, "nope", true, []byte("nope"))

	// Causes the connection to close (data expected, nil sent)
	// sendGlobalRequset(sshClientConn, "tcpip-forward", true, nil)

	// Causes the connection to close (data expected, invalid data sent)
	// sendGlobalRequset(sshClientConn, "tcpip-forward", true, []byte("nope"))

	sendGlobalRequset(sshClientConn, "tcpip-forward", false, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 1234}))
	sendGlobalRequset(sshClientConn, "cancel-tcpip-forward", false, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 1234}))

	sendGlobalRequset(sshClientConn, "tcpip-forward", false, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 0}))

	sendGlobalRequset(sshClientConn, "tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 1234}))
	sendGlobalRequset(sshClientConn, "cancel-tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 1234}))

	sendGlobalRequset(sshClientConn, "tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 0}))

	openChannel(sshClientConn, "nope", []byte("nope"), false)

	// Causes the connection to close (data expected, nil sent)
	// openChannel(sshClientConn, "direct-tcpip", nil, false)

	// Causes the connection to close (data expected, invalid data sent)
	// openChannel(sshClientConn, "direct-tcpip", []byte("nope"), false)

	tcpipChannel := openChannel(sshClientConn, "direct-tcpip", ssh.Marshal(struct {
		address           string
		port              uint32
		originatorAddress string
		originatorPort    uint32
	}{"github.com", 80, "127.0.0.1", 8080}), true)
	tcpipChannel.sendRequset("shell", true, nil)
	tcpipChannel.sendRequset("shell", true, []byte("nope"))
	tcpipChannel.sendRequset("exec", true, ssh.Marshal(struct {
		command string
	}{"true"}))
	tcpipChannel.sendRequset("exec", true, nil)
	tcpipChannel.sendRequset("exec", true, []byte("nope"))
	tcpipChannel.write("GET / HTTP/1.1\r\nHost: github.com\r\n\r\n", true)

	// Causes the connection to close (nil expected, data sent)
	// openChannel(sshClientConn, "session", []byte("nope"), false)

	sessionChannel := openChannel(sshClientConn, "session", nil, true)
	// Blocks indefinitely
	// sessionChannel.write("foo")
	sessionChannel.sendRequset("nope", true, []byte("nope"))
	// Causes the connection to close (data expected, nil sent)
	// sessionChannel.sendRequset("exec", true, nil)
	// Causes the connection to close (data expected, invalid data sent)
	// sessionChannel.sendRequset("exec", true, []byte("nope"))
	// Causes the connection to close (nil expected, data sent)
	// sessionChannel.sendRequset("shell", true, []byte("nope"))
	sessionChannel.sendRequset("exec", true, ssh.Marshal(struct {
		command string
	}{"true"}))

	sessionChannel = openChannel(sshClientConn, "session", nil, true)
	sessionChannel.sendRequset("shell", true, nil)
	sessionChannel.write("true\nfalse\nuname\n\x04", false)

	sessionChannel = openChannel(sshClientConn, "session", nil, true)
	sessionChannel.sendRequset("shell", true, nil)
	sessionChannel.write("true\nfalse\nuname\n", true)

	sessionChannel = openChannel(sshClientConn, "session", nil, true)
	terminalModes, err := base64.RawStdEncoding.DecodeString("gQAAJYCAAAAlgAEAAAADAgAAABwDAAAAfwQAAAAVBQAAAAQGAAAA/wcAAAD/CAAAABEJAAAAEwoAAAAaCwAAABkMAAAAEg0AAAAXDgAAABYRAAAAFBIAAAAPHgAAAAAfAAAAACAAAAAAIQAAAAAiAAAAACMAAAAAJAAAAAEmAAAAACcAAAABKAAAAAApAAAAASoAAAABMgAAAAEzAAAAATUAAAABNgAAAAE3AAAAADgAAAAAOQAAAAA6AAAAADsAAAABPAAAAAE9AAAAAT4AAAAARgAAAAFIAAAAAUkAAAAASgAAAABLAAAAAFoAAAABWwAAAAFcAAAAAF0AAAAAAA")
	if err != nil {
		panic(err)
	}
	sessionChannel.sendRequset("pty-req", true, ssh.Marshal(struct {
		Term                                   string
		Width, Height, PixelWidth, PixelHeight uint32
		Modes                                  string
	}{"xterm-256color", 120, 80, 0, 0, string(terminalModes)}))
	sessionChannel.sendRequset("shell", true, nil)
	sessionChannel.sendRequset("pty-req", true, ssh.Marshal(struct {
		Term                                   string
		Width, Height, PixelWidth, PixelHeight uint32
		Modes                                  string
	}{"xterm-256color", 120, 80, 0, 0, string(terminalModes)}))
	sessionChannel.sendRequset("exec", true, ssh.Marshal(struct {
		command string
	}{"true"}))
	sessionChannel.write("true\rfalse\runame\r\x04", false)

	sessionChannel = openChannel(sshClientConn, "session", nil, true)
	sessionChannel.sendRequset("pty-req", true, ssh.Marshal(struct {
		Term                                   string
		Width, Height, PixelWidth, PixelHeight uint32
		Modes                                  string
	}{"xterm-256color", 120, 80, 0, 0, string(terminalModes)}))
	sessionChannel.sendRequset("shell", true, nil)
	sessionChannel.write("true\rfalse\runame\r", true)

	sendGlobalRequset(sshClientConn, "no-more-sessions@openssh.com", true, nil)

	sendGlobalRequset(sshClientConn, "no-more-sessions@openssh.com", false, nil)

	// Causes the connection to close
	// openChannel(sshClientConn, "session", nil, false)

	time.Sleep(5 * time.Second)
}
