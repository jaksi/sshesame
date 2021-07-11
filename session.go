package main

import (
	"bufio"
	"errors"
	"io"
	"strings"

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

type sessionContext struct {
	ssh.Channel
	inputChan chan string
	errorChan chan error
	active    bool
	pty       bool
}

type scannerReadLiner struct {
	scanner   *bufio.Scanner
	inputChan chan<- string
}

func (r scannerReadLiner) ReadLine() (string, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return "", err
		}
		return "", io.EOF
	}
	line := r.scanner.Text()
	r.inputChan <- line
	return line, nil
}

type terminalReadLiner struct {
	terminal  *term.Terminal
	inputChan chan<- string
}

func (r terminalReadLiner) ReadLine() (string, error) {
	line, err := r.terminal.ReadLine()
	if err == nil || line != "" {
		r.inputChan <- line
	}
	return line, err
}

func (channel *sessionContext) handleProgram(program []string) bool {
	if channel.active {
		warningLogger.Printf("A program is already active")
		return false
	}
	channel.active = true
	var stdin readLiner
	var stdout, stderr io.Writer
	if channel.pty {
		terminal := term.NewTerminal(channel, "")
		stdin = terminalReadLiner{terminal, channel.inputChan}
		stdout = terminal
		stderr = terminal
	} else {
		stdin = scannerReadLiner{bufio.NewScanner(channel), channel.inputChan}
		stdout = channel
		stderr = channel.Stderr()
	}
	go func() {
		defer close(channel.inputChan)
		defer close(channel.errorChan)
		result, err := executeProgram(commandContext{program, stdin, stdout, stderr, channel.pty})
		if err == io.EOF {
			err = nil
		}
		if err == nil && channel.pty {
			_, err = channel.Write([]byte("\r\n"))
		}
		if err == nil {
			_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct {
				ExitStatus uint32
			}{result}))
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

func (channel *sessionContext) handleRequest(request interface{}) (bool, error) {
	switch payload := request.(type) {
	case *ptyRequest:
		if channel.pty {
			return false, errors.New("a pty-req request was already sent")
		}
		channel.pty = true
	case *shellRequest:
		if !channel.handleProgram(shellProgram) {
			return false, nil
		}
	case *execRequestPayload:
		if !channel.handleProgram(strings.Fields(payload.Command)) {
			return false, nil
		}
	case *subsystemRequestPayload:
		if !channel.handleProgram(strings.Fields(payload.Subsystem)) {
			return false, nil
		}
	}
	return true, nil
}

func handleSessionChannel(newChannel ssh.NewChannel, context channelContext) error {
	if context.noMoreSessions {
		return errors.New("nore more sessions were supposed to be requested")
	}
	if len(newChannel.ExtraData()) != 0 {
		return errors.New("invalid channel data")
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	context.logEvent(sessionLog{
		channelLog: channelLog{
			ChannelID: context.channelID,
		},
	})
	defer context.logEvent(sessionCloseLog{
		channelLog: channelLog{
			ChannelID: context.channelID,
		},
	})

	inputChan := make(chan string)
	errorChan := make(chan error)
	session := sessionContext{channel, inputChan, errorChan, false, false}

	for inputChan != nil || errorChan != nil || requests != nil {
		select {
		case input, ok := <-inputChan:
			if !ok {
				inputChan = nil
				continue
			}
			context.logEvent(sessionInputLog{
				channelLog: channelLog{
					ChannelID: context.channelID,
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
				if !session.active {
					close(inputChan)
					close(errorChan)
				}
				continue
			}
			context.logEvent(debugChannelRequestLog{
				channelLog:  channelLog{ChannelID: context.channelID},
				RequestType: request.Type,
				WantReply:   request.WantReply,
				Payload:     string(request.Payload),
			})
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
				context.logEvent(payload.logEntry(context.channelID))
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
