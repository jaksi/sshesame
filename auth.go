package main

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func authLogCallback(conn ssh.ConnMetadata, method string, err error) {
	connMetadata{conn}.getLogEntry().WithFields(logrus.Fields{
		"method":  method,
		"success": err == nil,
	}).Infoln("Client attempted to authenticate")
}

func (cfg *config) getPasswordCallback() func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if !cfg.PasswordAuth.Enabled {
		return nil
	}
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		connMetadata{conn}.getLogEntry().WithFields(logrus.Fields{
			"password": string(password),
			"success":  cfg.PasswordAuth.Accepted,
		}).Infoln("Password authentication attempted")
		if !cfg.PasswordAuth.Accepted {
			return nil, errors.New("")
		}
		return nil, nil
	}
}

func (cfg *config) getPublicKeyCallback() func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if !cfg.PublicKeyAuth.Enabled {
		return nil
	}
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		connMetadata{conn}.getLogEntry().WithFields(logrus.Fields{
			"public_key_fingerprint": ssh.FingerprintSHA256(key),
			"success":                cfg.PublicKeyAuth.Accepted,
		}).Infoln("Public key authentication attempted")
		if !cfg.PublicKeyAuth.Accepted {
			return nil, errors.New("")
		}
		return nil, nil
	}
}

func (cfg *config) getKeyboardInteractiveCallback() func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	if !cfg.KeyboardInteractiveAuth.Enabled {
		return nil
	}
	var keyboardInteractiveQuestions []string
	var keyboardInteractiveEchos []bool
	for _, question := range cfg.KeyboardInteractiveAuth.Questions {
		keyboardInteractiveQuestions = append(keyboardInteractiveQuestions, question.Text)
		keyboardInteractiveEchos = append(keyboardInteractiveEchos, question.Echo)
	}
	return func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		answers, err := client(conn.User(), cfg.KeyboardInteractiveAuth.Instruction, keyboardInteractiveQuestions, keyboardInteractiveEchos)
		if err != nil {
			log.Println("Failed to process keyboard interactive authentication:", err)
			return nil, errors.New("")
		}
		connMetadata{conn}.getLogEntry().WithFields(logrus.Fields{
			"answers": strings.Join(answers, ", "),
			"success": cfg.KeyboardInteractiveAuth.Accepted,
		}).Infoln("Keyboard interactive authentication attempted")
		if !cfg.KeyboardInteractiveAuth.Accepted {
			return nil, errors.New("")
		}
		return nil, nil
	}
}

func (cfg *config) getBannerCallback() func(conn ssh.ConnMetadata) string {
	if cfg.Banner == "" {
		return nil
	}
	banner := strings.ReplaceAll(strings.ReplaceAll(cfg.Banner, "\r\n", "\n"), "\n", "\r\n")
	if !strings.HasSuffix(banner, "\r\n") {
		banner = fmt.Sprintf("%v\r\n", banner)
	}
	return func(conn ssh.ConnMetadata) string { return banner }
}
