package main

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func handleSessionChannel(channel ssh.Channel, channelInput chan<- string) error {
	terminal := term.NewTerminal(channel, "$ ")
	for {
		line, err := terminal.ReadLine()
		if err != nil {
			if line != "" {
				channelInput <- line
			}
			return err
		}
		channelInput <- line
	}
}
