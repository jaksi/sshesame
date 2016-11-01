package main

import (
	"golang.org/x/crypto/ssh"
	"log"
	"net"
)

func handleRequests(remoteAddr net.Addr, channel string, requests <-chan *ssh.Request) {
	for request := range requests {
		log.Printf("Request: client=%v, channel=%v, type=%v, payload=%v\n", remoteAddr, channel, request.Type, request.Payload)
		if request.WantReply {
			request.Reply(true, nil)
		}
	}
}
