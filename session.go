package main

import (
	"bufio"
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type ptyRequest struct {
	Term                                   string
	Width, Height, PixelWidth, PixelHeight uint32
	Modes                                  string
}

func (request ptyRequest) reply() []byte {
	return nil
}
func (request ptyRequest) logEntry(channelID int) logEntry {
	return ptyLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Terminal: request.Term,
		Width:    request.Width,
		Height:   request.Height,
	}
}

type shellRequest struct{}

func (request shellRequest) reply() []byte {
	return nil
}
func (request shellRequest) logEntry(channelID int) logEntry {
	return shellLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
	}
}

type x11RequestPayload struct {
	SingleConnection         bool
	AuthProtocol, AuthCookie string
	ScreenNumber             uint32
}

func (request x11RequestPayload) reply() []byte {
	return nil
}
func (request x11RequestPayload) logEntry(channelID int) logEntry {
	return x11Log{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Screen: request.ScreenNumber,
	}
}

type envRequestPayload struct {
	Name, Value string
}

func (request envRequestPayload) reply() []byte {
	return nil
}
func (request envRequestPayload) logEntry(channelID int) logEntry {
	return envLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Name:  request.Name,
		Value: request.Value,
	}
}

type execRequestPayload struct {
	Command string
}

func (request execRequestPayload) reply() []byte {
	return nil
}
func (request execRequestPayload) logEntry(channelID int) logEntry {
	return execLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Command: request.Command,
	}
}

type subsystemRequestPayload struct {
	Subsystem string
}

func (request subsystemRequestPayload) reply() []byte {
	return nil
}
func (request subsystemRequestPayload) logEntry(channelID int) logEntry {
	return subsystemLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Subsystem: request.Subsystem,
	}
}

type windowChangeRequestPayload struct {
	Width, Height, PixelWidth, PixelHeight uint32
}

func (request windowChangeRequestPayload) reply() []byte {
	return nil
}
func (request windowChangeRequestPayload) logEntry(channelID int) logEntry {
	return windowChangeLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Width:  request.Width,
		Height: request.Height,
	}
}

var sessionRequestParsers = map[string]channelRequestPayloadParser{
	"pty-req": func(data []byte) (channelRequestPayload, error) {
		payload := &ptyRequest{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"shell": func(data []byte) (channelRequestPayload, error) {
		if len(data) != 0 {
			return nil, errors.New("invalid request payload")
		}
		return &shellRequest{}, nil
	},
	"x11-req": func(data []byte) (channelRequestPayload, error) {
		payload := &x11RequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"env": func(data []byte) (channelRequestPayload, error) {
		payload := &envRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"exec": func(data []byte) (channelRequestPayload, error) {
		payload := &execRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"subsystem": func(data []byte) (channelRequestPayload, error) {
		payload := &subsystemRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"window-change": func(data []byte) (channelRequestPayload, error) {
		payload := &windowChangeRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
}

type sessionChannel struct {
	ssh.Channel
	metadata  channelMetadata
	inputChan chan string
	errorChan chan error
	active    bool
	pty       bool
}

func (channel *sessionChannel) handleProgram() bool {
	if channel.active {
		warningLogger.Printf("A program is already active")
		return false
	}
	channel.active = true
	go func() {
		defer close(channel.inputChan)
		defer close(channel.errorChan)
		var err error
		if channel.pty {
			terminal := term.NewTerminal(channel, "$ ")
			var line string
			for err == nil {
				line, err = terminal.ReadLine()
				channel.inputChan <- line
			}
			if err == io.EOF {
				err = nil
			}
		} else {
			scanner := bufio.NewScanner(channel)
			for scanner.Scan() {
				channel.inputChan <- scanner.Text()
			}
			err = scanner.Err()
		}
		if err == nil && channel.pty {
			_, err = channel.Write([]byte("\r\n"))
		}
		if err == nil {
			_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct {
				ExitStatus uint32
			}{0}))
		}
		if err == nil && channel.pty {
			_, err = channel.SendRequest("eow@openssh.com", false, nil)
		}
		if err == nil {
			err = channel.CloseWrite()
		}
		if err == nil {
			err = channel.Close()
		}
		channel.errorChan <- err
	}()
	return true
}

func (channel *sessionChannel) handleRequest(request interface{}) (bool, error) {
	switch request.(type) {
	case *ptyRequest:
		if channel.pty {
			return false, errors.New("a pty-req request was already sent")
		}
		channel.pty = true
	case *shellRequest, *execRequestPayload, *subsystemRequestPayload:
		if !channel.handleProgram() {
			return false, nil
		}
	}
	return true, nil
}

func handleSessionChannel(newChannel ssh.NewChannel, metadata channelMetadata) error {
	if len(newChannel.ExtraData()) != 0 {
		return errors.New("invalid channel data")
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	metadata.logEvent(sessionLog{
		channelLog: channelLog{
			ChannelID: metadata.channelID,
		},
	})
	defer metadata.logEvent(sessionCloseLog{
		channelLog: channelLog{
			ChannelID: metadata.channelID,
		},
	})

	inputChan := make(chan string)
	errorChan := make(chan error)
	session := sessionChannel{channel, metadata, inputChan, errorChan, false, false}

	for inputChan != nil || errorChan != nil || requests != nil {
		select {
		case input, ok := <-inputChan:
			if !ok {
				inputChan = nil
				continue
			}
			metadata.logEvent(sessionInputLog{
				channelLog: channelLog{
					ChannelID: metadata.channelID,
				},
				Input: input,
			})
		case err, ok := <-errorChan:
			if !ok {
				errorChan = nil
				continue
			}
			if err != nil {
				return err
			}
		case request, ok := <-requests:
			if !ok {
				requests = nil
				continue
			}
			parser := sessionRequestParsers[request.Type]
			if parser == nil {
				warningLogger.Printf("Unsupported session request type %v", request.Type)
				if request.WantReply {
					if err := request.Reply(false, nil); err != nil {
						return err
					}
				}
				continue
			}
			payload, err := parser(request.Payload)
			if err != nil {
				return err
			}
			accept, err := session.handleRequest(payload)
			if err != nil {
				return err
			}
			if accept {
				metadata.logEvent(payload.logEntry(metadata.channelID))
			}
			if request.WantReply {
				if err := request.Reply(accept, payload.reply()); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
