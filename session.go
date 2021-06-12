package main

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func handleSessionChannel(channel ssh.Channel, input chan<- string) error {
	terminal := term.NewTerminal(channel, "$ ")
	for {
		line, err := terminal.ReadLine()
		if line != "" {
			input <- line
		}
		if err != nil {
			return err
		}
	}
}
