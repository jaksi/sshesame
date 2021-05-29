package main

import (
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

func handleSessionChannel(channel ssh.Channel) (string, error) {
	channelInputBytes, err := ioutil.ReadAll(channel)
	return string(channelInputBytes), err
}
