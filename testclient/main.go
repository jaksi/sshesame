package main

import (
	"bufio"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

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
			log.Printf("<host key\n  %#v\n", key)
			return nil
		},
		BannerCallback: func(message string) error {
			log.Printf("<banner\n  %#v\n", message)
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
			log.Panicln(err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			log.Panicln(err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Panicln(err)
	}
	defer conn.Close()

	sshClientConn, channels, requests, err := ssh.NewClientConn(conn, *addr, config)
	if err != nil {
		log.Panicln(err)
	}
	defer sshClientConn.Close()
	log.Printf(">connect\n  %#v\n", string(sshClientConn.ServerVersion()))

	if _, _, err := sshClientConn.SendRequest("no-more-sessions@openssh.com", false, nil); err != nil {
		log.Panicln(err)
	}
	log.Printf(">no-more-sessions")

	go func() {
		for request := range requests {
			log.Printf("<global request\n  %#v\n  %#v\n  %#v\n", request.Type, request.WantReply, request.Payload)
			if request.WantReply {
				log.Panicln("WantReply")
			}
		}
	}()

	go func() {
		for channel := range channels {
			log.Panicf("<channel\n  %#v\n", channel)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	accepted, reply, err := sshClientConn.SendRequest("nope", true, nil)
	if err != nil {
		log.Panicln(err)
	}
	log.Printf(">request nope\n  %#v\n  %#v\n", accepted, reply)

	time.Sleep(100 * time.Millisecond)
	accepted, reply, err = sshClientConn.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 1234}))
	if err != nil {
		log.Panicln(err)
	}
	log.Printf(">request tcpip-forward\n  %#v\n  %#v\n", accepted, reply)

	time.Sleep(100 * time.Millisecond)
	accepted, reply, err = sshClientConn.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		string
		uint32
	}{"127.0.0.1", 0}))
	if err != nil {
		log.Panicln(err)
	}
	log.Printf(">request tcpip-forward 0\n  %#v\n  %#v\n", accepted, reply)

	time.Sleep(100 * time.Millisecond)
	_, _, err = sshClientConn.SendRequest("cancel-tcpip-forward", false, ssh.Marshal(struct {
		address string
		port    uint32
	}{"127.0.0.1", 1234}))
	if err != nil {
		log.Panicln(err)
	}
	log.Printf(">request cancel-tcpip-forward\n")

	time.Sleep(100 * time.Millisecond)
	tcpChannel, tcpRequests, err := sshClientConn.OpenChannel("direct-tcpip", ssh.Marshal(struct {
		address           string
		port              uint32
		originatorAddress string
		originatorPort    uint32
	}{"github.com", 80, "127.0.0.1", 8080}))
	if err != nil {
		log.Panicln(err)
	}
	defer tcpChannel.Close()
	log.Printf(">channel direct-tcpip\n")

	go func() {
		for request := range tcpRequests {
			log.Printf("<direct-tcpip request\n  %#v\n  %#v\n  %#v\n", request.Type, request.WantReply, request.Payload)
			if request.WantReply {
				log.Panicln("WantReply")
			}
		}
		log.Printf("<direct-tcpip requests done\n")
	}()
	go func() {
		scanner := bufio.NewScanner(tcpChannel)
		for scanner.Scan() {
			log.Printf("<direct-tcpip data\n  %#v\n", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Panicln(err)
		}
		log.Printf("<direct-tcpip data done\n")
	}()

	time.Sleep(100 * time.Millisecond)
	accepted, err = tcpChannel.SendRequest("shell", true, nil)
	if err != nil {
		log.Panicln(err)
	}
	log.Printf(">direct-tcpip request shell\n  %#v\n", accepted)

	time.Sleep(100 * time.Millisecond)
	if _, err := tcpChannel.Write([]byte("GET / HTTP/1.1\r\nHost: github.com\r\n\r\n")); err != nil {
		log.Panicln(err)
	}
	log.Printf(">direct-tcpip data <HTTP request>\n")

	time.Sleep(5 * time.Second)
}
