package main

import (
	"encoding/base64"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func getLogEntry(conn ssh.ConnMetadata) *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"client_version": string(conn.ClientVersion()),
		"session_id":     base64.RawStdEncoding.EncodeToString(conn.SessionID()),
		"user":           conn.User(),
		"remote_addr":    conn.RemoteAddr().String(),
	})
}

func (conn channelMetadata) getLogEntry() *logrus.Entry {
	return getLogEntry(conn.conn).WithField("channel_id", conn.channelID)
}
