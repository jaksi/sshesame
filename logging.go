package main

import (
	"encoding/base64"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type connMetadata struct {
	ssh.ConnMetadata
}

type channelMetadata struct {
	connMetadata
	channelID int
}

func (metadata connMetadata) getLogEntry() *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"client_version": string(metadata.ClientVersion()),
		"session_id":     base64.RawStdEncoding.EncodeToString(metadata.SessionID()),
		"user":           metadata.User(),
		"remote_address": metadata.RemoteAddr().String(),
	})
}

func (metadata channelMetadata) getLogEntry() *logrus.Entry {
	return metadata.connMetadata.getLogEntry().WithField("channel_id", metadata.channelID)
}
