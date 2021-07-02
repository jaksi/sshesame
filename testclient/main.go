package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

var start time.Time

func log(message string) {
	fmt.Println(math.Round(time.Since(start).Seconds()), message)
}

type sshConn struct {
	ssh.Conn
}

func (conn *sshConn) sendGlobalRequset(name string, wantReply bool, payload []byte) {
	time.Sleep(500 * time.Millisecond)
	accepted, response, err := conn.SendRequest(name, wantReply, payload)
	log(fmt.Sprintf(">global request %v\n  %#v\n  %#v\n", name, accepted, response))
	if err != nil {
		panic(err)
	}
}

func (conn *sshConn) openChannel(name string, data []byte, success bool) *sshChannel {
	time.Sleep(500 * time.Millisecond)
	channel, requests, err := conn.OpenChannel(name, data)
	log(fmt.Sprintf(">channel %v\n  %#v\n", name, err))
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
			log(fmt.Sprintf("<channel %v request\n  %#v\n  %#v\n  %#v\n", name, request.Type, request.WantReply, request.Payload))
			if request.WantReply {
				panic("WantReply")
			}
		}
		time.Sleep(100 * time.Millisecond)
		log(fmt.Sprintf("<close channel %v requests\n", name))
	}()
	go func() {
		scanner := bufio.NewScanner(channel)
		for scanner.Scan() {
			log(fmt.Sprintf("<channel %v stdout\n  %#v\n", name, scanner.Text()))
		}
		time.Sleep(100 * time.Millisecond)
		log(fmt.Sprintf("<close channel %v stdout\n", name))
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}()
	go func() {
		scanner := bufio.NewScanner(channel.Stderr())
		for scanner.Scan() {
			log(fmt.Sprintf("<channel %v stderr\n  %#v\n", name, scanner.Text()))
		}
		time.Sleep(100 * time.Millisecond)
		log(fmt.Sprintf("<close channel %v stderr\n", name))
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}()
	return &sshChannel{channel, name}
}

type sshChannel struct {
	ssh.Channel
	name string
}

func (channel *sshChannel) sendRequset(name string, wantReply bool, payload []byte) {
	time.Sleep(500 * time.Millisecond)
	accepted, err := channel.SendRequest(name, wantReply, payload)
	log(fmt.Sprintf(">channel %v request %v\n  %#v\n", channel.name, name, accepted))
	if err != nil {
		panic(err)
	}
}

func (channel *sshChannel) write(data string) {
	time.Sleep(500 * time.Millisecond)
	_, err := channel.Write([]byte(data))
	log(fmt.Sprintf(">channel %v data\n  %#v\n", channel.name, data))
	if err != nil {
		panic(err)
	}
}

func (channel *sshChannel) close() {
	time.Sleep(500 * time.Millisecond)
	err := channel.CloseWrite()
	log(fmt.Sprintf(">close channel %v\n", channel.name))
	if err != nil {
		panic(err)
	}
}

func (conn *sshConn) tcpTest() {
	conn.sendGlobalRequset("tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 0}))
	conn.sendGlobalRequset("tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 1234}))
	conn.sendGlobalRequset("cancel-tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 1234}))
	conn.sendGlobalRequset("no-more-sessions@openssh.com", false, nil)
	tcpipChannel := conn.openChannel("direct-tcpip", ssh.Marshal(struct {
		address           string
		port              uint32
		originatorAddress string
		originatorPort    uint32
	}{"github.com", 80, "127.0.0.1", 8080}), true)
	tcpipChannel.write("GET / HTTP/1.1\r\nHost: github.com\r\n\r\n")
	tcpipChannel.close()
}

func (conn *sshConn) rawShellTest() {
	session := conn.openChannel("session", nil, true)
	conn.sendGlobalRequset("no-more-sessions@openssh.com", false, nil)
	session.sendRequset("x11-req", true, ssh.Marshal(struct {
		SingleConnection         bool
		AuthProtocol, AuthCookie string
		ScreenNumber             uint32
	}{false, "MIT-MAGIC-COOKIE-1", "e16b9dbcaa8678ae85572677d847a3a5", 0}))
	session.sendRequset("env", false, ssh.Marshal(struct {
		Name, Value string
	}{"LANG", "en_IE.UTF-8"}))
	session.sendRequset("shell", true, nil)
	session.write("false\n")
	session.write("true\n")
	session.close()
}

func (conn *sshConn) rawExecTest() {
	session := conn.openChannel("session", nil, true)
	conn.sendGlobalRequset("no-more-sessions@openssh.com", false, nil)
	session.sendRequset("x11-req", true, ssh.Marshal(struct {
		SingleConnection         bool
		AuthProtocol, AuthCookie string
		ScreenNumber             uint32
	}{false, "MIT-MAGIC-COOKIE-1", "e16b9dbcaa8678ae85572677d847a3a5", 0}))
	session.sendRequset("env", false, ssh.Marshal(struct {
		Name, Value string
	}{"LANG", "en_IE.UTF-8"}))
	session.sendRequset("exec", true, ssh.Marshal(struct {
		Command string
	}{"sh"}))
	session.write("false\n")
	session.write("true\n")
	session.close()
}

func (conn *sshConn) ptyShellTest() {
	session := conn.openChannel("session", nil, true)
	conn.sendGlobalRequset("no-more-sessions@openssh.com", false, nil)
	session.sendRequset("x11-req", true, ssh.Marshal(struct {
		SingleConnection         bool
		AuthProtocol, AuthCookie string
		ScreenNumber             uint32
	}{false, "MIT-MAGIC-COOKIE-1", "e16b9dbcaa8678ae85572677d847a3a5", 0}))
	terminalModes, err := base64.RawStdEncoding.DecodeString("gQAAJYCAAAAlgAEAAAADAgAAABwDAAAAfwQAAAAVBQAAAAQGAAAA/wcAAAD/CAAAABEJAAAAEwoAAAAaCwAAABkMAAAAEg0AAAAXDgAAABYRAAAAFBIAAAAPHgAAAAAfAAAAACAAAAAAIQAAAAAiAAAAACMAAAAAJAAAAAEmAAAAACcAAAABKAAAAAApAAAAASoAAAABMgAAAAEzAAAAATUAAAABNgAAAAE3AAAAADgAAAAAOQAAAAA6AAAAADsAAAABPAAAAAE9AAAAAT4AAAAARgAAAAFIAAAAAUkAAAAASgAAAABLAAAAAFoAAAABWwAAAAFcAAAAAF0AAAAAAA")
	if err != nil {
		panic(err)
	}
	session.sendRequset("pty-req", true, ssh.Marshal(struct {
		Term                                   string
		Width, Height, PixelWidth, PixelHeight uint32
		Modes                                  string
	}{"xterm-256color", 80, 24, 123, 456, string(terminalModes)}))
	session.sendRequset("env", false, ssh.Marshal(struct {
		Name, Value string
	}{"LANG", "en_IE.UTF-8"}))
	session.sendRequset("shell", true, nil)
	session.write("false\r")
	session.write("true\r")
	session.write("\x04")
}

func (conn *sshConn) ptyExecTest() {
	session := conn.openChannel("session", nil, true)
	conn.sendGlobalRequset("no-more-sessions@openssh.com", false, nil)
	session.sendRequset("x11-req", true, ssh.Marshal(struct {
		SingleConnection         bool
		AuthProtocol, AuthCookie string
		ScreenNumber             uint32
	}{false, "MIT-MAGIC-COOKIE-1", "e16b9dbcaa8678ae85572677d847a3a5", 0}))
	terminalModes, err := base64.RawStdEncoding.DecodeString("gQAAJYCAAAAlgAEAAAADAgAAABwDAAAAfwQAAAAVBQAAAAQGAAAA/wcAAAD/CAAAABEJAAAAEwoAAAAaCwAAABkMAAAAEg0AAAAXDgAAABYRAAAAFBIAAAAPHgAAAAAfAAAAACAAAAAAIQAAAAAiAAAAACMAAAAAJAAAAAEmAAAAACcAAAABKAAAAAApAAAAASoAAAABMgAAAAEzAAAAATUAAAABNgAAAAE3AAAAADgAAAAAOQAAAAA6AAAAADsAAAABPAAAAAE9AAAAAT4AAAAARgAAAAFIAAAAAUkAAAAASgAAAABLAAAAAFoAAAABWwAAAAFcAAAAAF0AAAAAAA")
	if err != nil {
		panic(err)
	}
	session.sendRequset("pty-req", true, ssh.Marshal(struct {
		Term                                   string
		Width, Height, PixelWidth, PixelHeight uint32
		Modes                                  string
	}{"xterm-256color", 80, 24, 123, 456, string(terminalModes)}))
	session.sendRequset("env", false, ssh.Marshal(struct {
		Name, Value string
	}{"LANG", "en_IE.UTF-8"}))
	session.sendRequset("exec", true, ssh.Marshal(struct {
		Command string
	}{"sh"}))
	session.write("false\r")
	session.write("true\r")
	session.write("\x04")
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
			log(fmt.Sprintf("<host key\n  %#v\n", key))
			return nil
		},
		BannerCallback: func(message string) error {
			log(fmt.Sprintf("<banner\n  %#v\n", message))
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

	start = time.Now()

	clientConn, channels, requests, err := ssh.NewClientConn(conn, *addr, config)
	if err != nil {
		panic(err)
	}
	defer clientConn.Close()
	log(fmt.Sprintf(">connect\n  %#v\n", string(clientConn.ServerVersion())))

	go func() {
		for request := range requests {
			log(fmt.Sprintf("<global request\n  %#v\n  %#v\n  %#v\n", request.Type, request.WantReply, request.Payload))
			if request.WantReply {
				panic("WantReply")
			}
		}
		time.Sleep(100 * time.Millisecond)
		log("<close global requests\n")
	}()

	go func() {
		for channel := range channels {
			panic(channel)
		}
		time.Sleep(100 * time.Millisecond)
		log("<close channels\n")
	}()

	sshClientConn := sshConn{clientConn}

	//sshClientConn.tcpTest()
	//sshClientConn.rawShellTest() // perfect
	//sshClientConn.rawExecTest() // perfect
	//sshClientConn.ptyShellTest() // perfect
	sshClientConn.ptyExecTest() // perfect

	time.Sleep(5 * time.Second)
}
