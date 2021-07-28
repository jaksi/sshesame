package main

import (
	"bufio"
	"errors"
	"io"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type ptyRequestPayload struct {
	Term                                   string
	Width, Height, PixelWidth, PixelHeight uint32
	Modes                                  string
}

func (request ptyRequestPayload) reply() []byte {
	return nil
}
func (request ptyRequestPayload) logEntry(channelID int) logEntry {
	return ptyLog{
		channelLog: channelLog{
			ChannelID: channelID,
		},
		Terminal: request.Term,
		Width:    request.Width,
		Height:   request.Height,
	}
}

type shellRequestPayload struct{}

func (request shellRequestPayload) reply() []byte {
	return nil
}
func (request shellRequestPayload) logEntry(channelID int) logEntry {
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

type sessionContext struct {
	channelContext
	ssh.Channel
	inputChan chan string
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

type clientEOFError struct{}

var clientEOF = clientEOFError{}

func (clientEOFError) Error() string {
	return "Client EOF"
}

func (r terminalReadLiner) ReadLine() (string, error) {
	line, err := r.terminal.ReadLine()
	if err == nil || line != "" {
		r.inputChan <- line
	}
	if err == io.EOF {
		return line, clientEOF
	}
	return line, err
}

func (context *sessionContext) handleProgram(program []string) {
	context.active = true
	var stdin readLiner
	var stdout, stderr io.Writer
	if context.pty {
		terminal := term.NewTerminal(context, "")
		stdin = terminalReadLiner{terminal, context.inputChan}
		stdout = terminal
		stderr = terminal
	} else {
		stdin = scannerReadLiner{bufio.NewScanner(context), context.inputChan}
		stdout = context
		stderr = context.Stderr()
	}
	go func() {
		defer close(context.inputChan)

		result, err := executeProgram(commandContext{program, stdin, stdout, stderr, context.pty, context.User()})
		if err != nil && err != io.EOF && err != clientEOF {
			warningLogger.Printf("Error executing program: %s", err)
			return
		}

		if err == clientEOF && context.pty {
			if _, err := context.Write([]byte("\r\n")); err != nil {
				warningLogger.Printf("Error sending CRLF: %s", err)
				return
			}
		}

		if _, err := context.SendRequest("exit-status", false, ssh.Marshal(struct {
			ExitStatus uint32
		}{result})); err != nil {
			warningLogger.Printf("Error sending exit status: %s", err)
			return
		}

		if (context.pty && err == clientEOF) || err == nil {
			if _, err := context.SendRequest("eow@openssh.com", false, nil); err != nil {
				warningLogger.Printf("Error sending EOW: %s", err)
				return
			}
		}

		if err := context.CloseWrite(); err != nil {
			warningLogger.Printf("Error sending EOF: %s", err)
			return
		}

		if err := context.Close(); err != nil {
			warningLogger.Printf("Error closing channel: %s", err)
			return
		}
	}()
}

func (context *sessionContext) handleRequest(request *ssh.Request) error {
	switch request.Type {
	case "pty-req":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if !context.active {
			if context.pty {
				return errors.New("a pty is already requested")
			}
			payload := &ptyRequestPayload{}
			if err := ssh.Unmarshal(request.Payload, payload); err != nil {
				return err
			}
			context.logEvent(payload.logEntry(context.channelID))
			if err := request.Reply(true, payload.reply()); err != nil {
				return err
			}
			context.pty = true
			return nil
		}
	case "shell":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if !context.active {
			if len(request.Payload) != 0 {
				return errors.New("invalid request payload")
			}
			payload := &shellRequestPayload{}
			context.logEvent(payload.logEntry(context.channelID))
			if err := request.Reply(true, payload.reply()); err != nil {
				return err
			}
			context.active = true
			context.handleProgram(shellProgram)
			return nil
		}
	case "x11-req":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if !context.active {
			payload := &x11RequestPayload{}
			if err := ssh.Unmarshal(request.Payload, payload); err != nil {
				return err
			}
			context.logEvent(payload.logEntry(context.channelID))
			return request.Reply(true, payload.reply())
		}
	case "env":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if !context.active {
			payload := &envRequestPayload{}
			if err := ssh.Unmarshal(request.Payload, payload); err != nil {
				return err
			}
			context.logEvent(payload.logEntry(context.channelID))
			return request.Reply(true, payload.reply())
		}
	case "exec":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if !context.active {
			payload := &execRequestPayload{}
			if err := ssh.Unmarshal(request.Payload, payload); err != nil {
				return err
			}
			context.logEvent(payload.logEntry(context.channelID))
			if err := request.Reply(true, payload.reply()); err != nil {
				return err
			}
			context.active = true
			context.handleProgram(strings.Fields(payload.Command))
			return nil
		}
	case "subsystem":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		if !context.active {
			payload := &subsystemRequestPayload{}
			if err := ssh.Unmarshal(request.Payload, payload); err != nil {
				return err
			}
			context.logEvent(payload.logEntry(context.channelID))
			if err := request.Reply(true, payload.reply()); err != nil {
				return err
			}
			context.active = true
			context.handleProgram(strings.Fields(payload.Subsystem))
		}
	case "window-change":
		sessionChannelRequestsMetric.WithLabelValues(request.Type).Inc()
		payload := &windowChangeRequestPayload{}
		if err := ssh.Unmarshal(request.Payload, payload); err != nil {
			return err
		}
		context.logEvent(payload.logEntry(context.channelID))
		return request.Reply(true, payload.reply())
	default:
		sessionChannelRequestsMetric.WithLabelValues("unknown").Inc()
	}
	warningLogger.Printf("Rejected session request: %s", request.Type)
	return request.Reply(false, nil)
}

var (
	sessionChannelsMetric = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sshesame_session_channels_total",
		Help: "Total number of session channels",
	})
	activeSessionChannelsMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sshesame_active_session_channels",
		Help: "Number of active session channels",
	})
	sessionChannelRequestsMetric = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sshesame_session_channel_requests_total",
		Help: "Total number of session channel requests",
	}, []string{"type"})
)

func handleSessionChannel(newChannel ssh.NewChannel, context channelContext) error {
	if context.noMoreSessions {
		return errors.New("nore more sessions were supposed to be requested")
	}
	if len(newChannel.ExtraData()) != 0 {
		return errors.New("invalid channel data")
	}
	sessionChannelsMetric.Inc()
	activeSessionChannelsMetric.Inc()
	defer activeSessionChannelsMetric.Dec()
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
	session := sessionContext{context, channel, inputChan, false, false}

	for inputChan != nil || requests != nil {
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
		case request, ok := <-requests:
			if !ok {
				requests = nil
				if !session.active {
					close(inputChan)
				}
				continue
			}
			if err := session.handleRequest(request); err != nil {
				return err
			}
		}
	}

	return nil
}
