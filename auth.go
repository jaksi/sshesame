package main

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

func (cfg *config) getAuthLogCallback() func(conn ssh.ConnMetadata, method string, err error) {
	return func(conn ssh.ConnMetadata, method string, err error) {
		if method == "none" {
			connContext{ConnMetadata: conn, cfg: cfg}.logEvent(noAuthLog{authLog: authLog{
				User:     conn.User(),
				Accepted: err == nil,
			}})
		}
	}
}

func (cfg *config) getPasswordCallback() func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if !cfg.Auth.PasswordAuth.Enabled {
		return nil
	}
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		connContext{ConnMetadata: conn, cfg: cfg}.logEvent(passwordAuthLog{
			authLog: authLog{
				User:     conn.User(),
				Accepted: authAccepted(cfg.Auth.PasswordAuth.Accepted),
			},
			Password: string(password),
		})
		if !cfg.Auth.PasswordAuth.Accepted {
			return nil, errors.New("")
		}
		return nil, nil
	}
}

func (cfg *config) getPublicKeyCallback() func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if !cfg.Auth.PublicKeyAuth.Enabled {
		return nil
	}
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		connContext{ConnMetadata: conn, cfg: cfg}.logEvent(publicKeyAuthLog{
			authLog: authLog{
				User:     conn.User(),
				Accepted: authAccepted(cfg.Auth.PublicKeyAuth.Accepted),
			},
			PublicKeyFingerprint: ssh.FingerprintSHA256(key),
		})
		if !cfg.Auth.PublicKeyAuth.Accepted {
			return nil, errors.New("")
		}
		return nil, nil
	}
}

func (cfg *config) getKeyboardInteractiveCallback() func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	if !cfg.Auth.KeyboardInteractiveAuth.Enabled {
		return nil
	}
	var keyboardInteractiveQuestions []string
	var keyboardInteractiveEchos []bool
	for _, question := range cfg.Auth.KeyboardInteractiveAuth.Questions {
		keyboardInteractiveQuestions = append(keyboardInteractiveQuestions, question.Text)
		keyboardInteractiveEchos = append(keyboardInteractiveEchos, question.Echo)
	}
	return func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		answers, err := client(conn.User(), cfg.Auth.KeyboardInteractiveAuth.Instruction, keyboardInteractiveQuestions, keyboardInteractiveEchos)
		if err != nil {
			warningLogger.Printf("Failed to process keyboard interactive authentication: %v", err)
			return nil, errors.New("")
		}
		connContext{ConnMetadata: conn, cfg: cfg}.logEvent(keyboardInteractiveAuthLog{
			authLog: authLog{
				User:     conn.User(),
				Accepted: authAccepted(cfg.Auth.KeyboardInteractiveAuth.Accepted),
			},
			Answers: answers,
		})
		if !cfg.Auth.KeyboardInteractiveAuth.Accepted {
			return nil, errors.New("")
		}
		return nil, nil
	}
}

func (cfg *config) getBannerCallback() func(conn ssh.ConnMetadata) string {
	if cfg.SSHProto.Banner == "" {
		return nil
	}
	banner := strings.ReplaceAll(strings.ReplaceAll(cfg.SSHProto.Banner, "\r\n", "\n"), "\n", "\r\n")
	if !strings.HasSuffix(banner, "\r\n") {
		banner = fmt.Sprintf("%v\r\n", banner)
	}
	return func(conn ssh.ConnMetadata) string { return banner }
}
