package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type ptyRequestPayload struct {
	Term                                   string
	Width, Height, PixelWidth, PixelHeight uint32
	Modes                                  string
}

type parsedPTYRequestPayload struct {
	ptyRequestPayload
	parsedModes map[uint8]uint32
}

var opcodeStrings = map[uint8]string{
	0:   "TTY_OP_END",
	1:   "VINTR",
	2:   "VQUIT",
	3:   "VERASE",
	4:   "VKILL",
	5:   "VEOF",
	6:   "VEOL",
	7:   "VEOL2",
	8:   "VSTART",
	9:   "VSTOP",
	10:  "VSUSP",
	11:  "VDSUSP",
	12:  "VREPRINT",
	13:  "VWERASE",
	14:  "VLNEXT",
	15:  "VFLUSH",
	16:  "VSWTCH",
	17:  "VSTATUS",
	18:  "VDISCARD",
	30:  "IGNPAR",
	31:  "PARMRK",
	32:  "INPCK",
	33:  "ISTRIP",
	34:  "INLCR",
	35:  "IGNCR",
	36:  "ICRNL",
	37:  "IUCLC",
	38:  "IXON",
	39:  "IXANY",
	40:  "IXOFF",
	41:  "IMAXBEL",
	50:  "ISIG",
	51:  "ICANON",
	52:  "XCASE",
	53:  "ECHO",
	54:  "ECHOE",
	55:  "ECHOK",
	56:  "ECHONL",
	57:  "NOFLSH",
	58:  "TOSTOP",
	59:  "IEXTEN",
	60:  "ECHOCTL",
	61:  "ECHOKE",
	62:  "PENDIN",
	70:  "OPOST",
	71:  "OLCUC",
	72:  "ONLCR",
	73:  "OCRNL",
	74:  "ONOCR",
	75:  "ONLRET",
	90:  "CS7",
	91:  "CS8",
	92:  "PARENB",
	93:  "PARODD",
	128: "TTY_OP_ISPEED",
	129: "TTY_OP_OSPEED",
}

func (payload parsedPTYRequestPayload) String() string {
	terminalModes := []string{}
	for opcode, argument := range payload.parsedModes {
		opcodeString := opcodeStrings[opcode]
		if opcodeString == "" {
			opcodeString = fmt.Sprintf("OPCODE_%v", opcode)
		}
		terminalModes = append(terminalModes, fmt.Sprintf("%v=%v", opcodeString, argument))
	}
	return fmt.Sprintf("Term: %v, Size: %vx%v (%vx%v px), Modes: %v", payload.Term, payload.Width, payload.Height, payload.PixelWidth, payload.PixelHeight, strings.Join(terminalModes, ", "))
}

type shellRequestPayload struct{}

func (shellRequestPayload) String() string {
	return ""
}

type x11RequestPayload struct {
	SingleConnection         bool
	AuthProtocol, AuthCookie string
	ScreenNumber             uint32
}

func (payload x11RequestPayload) String() string {
	return fmt.Sprintf("Single connection: %v, Auth protocol: %v, Auth cookie: %v, Screen number: %v", payload.SingleConnection, payload.AuthProtocol, payload.AuthCookie, payload.ScreenNumber)
}

type envRequestPayload struct {
	Name, Value string
}

func (payload envRequestPayload) String() string {
	return fmt.Sprintf("%v=%v", payload.Name, payload.Value)
}

type execRequestPayload struct {
	Command string
}

func (payload execRequestPayload) String() string {
	return payload.Command
}

type subsystemRequestPayload struct {
	Subsystem string
}

func (payload subsystemRequestPayload) String() string {
	return payload.Subsystem
}

type windowChangeRequestPayload struct {
	Width, Height, PixelWidth, PixelHeight uint32
}

func (payload windowChangeRequestPayload) String() string {
	return fmt.Sprintf("%vx%v (%vx%v px)", payload.Width, payload.Height, payload.PixelWidth, payload.PixelHeight)
}

var requestParsers = map[string]requestPayloadParser{
	"pty-req": func(data []byte) (requestPayload, error) {
		payload := &ptyRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		parsedPayload := &parsedPTYRequestPayload{*payload, map[uint8]uint32{}}
		modeBytes := []byte(payload.Modes)
		for i := 0; i+4 < len(modeBytes); i += 5 {
			opcode := modeBytes[i]
			if opcode >= 160 {
				break
			}
			argument := binary.BigEndian.Uint32(modeBytes[i+1 : i+5])
			parsedPayload.parsedModes[opcode] = argument
		}
		return parsedPayload, nil
	},
	"shell": func(data []byte) (requestPayload, error) {
		if len(data) != 0 {
			return nil, errors.New("invalid request payload")
		}
		return &shellRequestPayload{}, nil
	},
	"x11-req": func(data []byte) (requestPayload, error) {
		payload := &x11RequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"env": func(data []byte) (requestPayload, error) {
		payload := &envRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"exec": func(data []byte) (requestPayload, error) {
		payload := &execRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"subsystem": func(data []byte) (requestPayload, error) {
		payload := &subsystemRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
	"window-change": func(data []byte) (requestPayload, error) {
		payload := &windowChangeRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
}

type sessionChannel struct {
	ssh.Channel
	inputChan chan string
	errorChan chan error
	active    bool
	pty       bool
}

func (channel *sessionChannel) handleRequest(request requestPayload) (bool, error) {
	switch request.(type) {
	case *parsedPTYRequestPayload:
		if channel.pty {
			return false, errors.New("a pty-req request was already sent on this session channel")
		}
		channel.pty = true
	case *shellRequestPayload, *execRequestPayload, *subsystemRequestPayload:
		if channel.active {
			log.Println("the session channel is already active")
			return false, nil
		}
		channel.active = true
		go func() {
			defer close(channel.inputChan)
			defer close(channel.errorChan)
			defer channel.Close()
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
			channel.errorChan <- err
		}()
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
	defer channel.Close()
	metadata.getLogEntry().Infoln("New channel accepted")
	defer metadata.getLogEntry().Infoln("Channel closed")

	inputChan := make(chan string)
	errorChan := make(chan error)

	session := sessionChannel{channel, inputChan, errorChan, false, false}

	for errorChan != nil || inputChan != nil || requests != nil {
		select {
		case input, ok := <-inputChan:
			if !ok {
				inputChan = nil
				continue
			}
			metadata.getLogEntry().WithField("input", input).Infoln("Channel input received")
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
			parser := requestParsers[request.Type]
			if parser == nil {
				log.Println("Unsupported session request type", request.Type)
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
			if !accept && request.WantReply {
				if err := request.Reply(false, nil); err != nil {
					return err
				}
			}
			metadata.getLogEntry().WithFields(logrus.Fields{
				"request_payload":    payload,
				"request_type":       request.Type,
				"request_want_reply": request.WantReply,
			}).Infoln("Channel request accepted")
			if request.WantReply {
				if err := request.Reply(true, nil); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
