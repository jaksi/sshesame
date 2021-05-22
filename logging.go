package main

import (
	"encoding/base64"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func getLogFields(conn ssh.ConnMetadata) logrus.Fields {
	return logrus.Fields{
		"client_version": string(conn.ClientVersion()),
		"session_id":     base64.RawStdEncoding.EncodeToString(conn.SessionID()),
		"user":           conn.User(),
		"remote_addr":    conn.RemoteAddr().String(),
	}
}
