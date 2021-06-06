package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type requestPayload fmt.Stringer

type requestPayloadParser func(data []byte) (requestPayload, error)

type tcpipRequestPayload struct {
	Address string
	Port    uint32
}

func (payload tcpipRequestPayload) String() string {
	return net.JoinHostPort(payload.Address, fmt.Sprint(payload.Port))
}

var globalRequestPayloadParsers = map[string]requestPayloadParser{
	"tcpip-forward": func(data []byte) (requestPayload, error) {
		payload := &tcpipRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
}

func handleGlobalRequests(requests <-chan *ssh.Request, metadata connMetadata) {
	for request := range requests {
		accept := true
		var payload requestPayload
		if parser := globalRequestPayloadParsers[request.Type]; parser == nil {
			log.Println("Unsupported global request type", request.Type)
			accept = false
		} else {
			var err error
			payload, err = parser(request.Payload)
			if err != nil {
				log.Println("Failed to parse global request payload", err)
				accept = false
			}
		}
		var payloadString string
		if payload != nil {
			payloadString = fmt.Sprint(payload)
		} else {
			payloadString = base64.RawStdEncoding.EncodeToString(request.Payload)
		}
		metadata.getLogEntry().WithFields(logrus.Fields{
			"request_payload":    payloadString,
			"request_type":       request.Type,
			"request_want_reply": request.WantReply,
			"accepted":           accept,
		}).Infoln("Global request received")

		if request.WantReply {
			var response []byte
			switch payload := payload.(type) {
			case *tcpipRequestPayload:
				if payload.Port == 0 {
					response = ssh.Marshal(struct{ port uint32 }{uint32(rand.Intn(65536-1024) + 1024)})
				}
			}
			if err := request.Reply(accept, response); err != nil {
				log.Println("Failed to reply to global request:", err)
				continue
			}
		}
	}
}

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

type signalRequestPayload struct {
	Signal string
}

func (payload signalRequestPayload) String() string {
	return payload.Signal
}

var channelRequestPayloadParsers = map[string]requestPayloadParser{
	"pty-req": func(data []byte) (requestPayload, error) {
		payload := &ptyRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		parsedPayload := parsedPTYRequestPayload{*payload, map[uint8]uint32{}}
		modeBytes := []byte(payload.Modes)
		for i := 0; i < len(modeBytes); i += 5 {
			opcode := modeBytes[i]
			if opcode >= 160 {
				break
			}
			argument := binary.BigEndian.Uint32(modeBytes[i+1 : i+5])
			parsedPayload.parsedModes[opcode] = argument
		}
		return parsedPayload, nil
	},
	"shell": func(data []byte) (requestPayload, error) { return nil, nil },
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
	"signal": func(data []byte) (requestPayload, error) {
		payload := &signalRequestPayload{}
		if err := ssh.Unmarshal(data, payload); err != nil {
			return nil, err
		}
		return payload, nil
	},
}

func handleChannelRequests(requests <-chan *ssh.Request, metadata channelMetadata) {
	for request := range requests {
		accept := true
		var payload requestPayload
		if parser := channelRequestPayloadParsers[request.Type]; parser == nil {
			log.Println("Unsupported channel request type", request.Type)
			accept = false
		} else {
			var err error
			payload, err = parser(request.Payload)
			if err != nil {
				log.Println("Failed to parse channel request payload", err)
				accept = false
			}
		}
		var payloadString string
		if payload != nil {
			payloadString = fmt.Sprint(payload)
		} else {
			payloadString = base64.RawStdEncoding.EncodeToString(request.Payload)
		}
		metadata.getLogEntry().WithFields(logrus.Fields{
			"request_payload":    payloadString,
			"request_type":       request.Type,
			"request_want_reply": request.WantReply,
			"accepted":           accept,
		}).Infoln("Channel request received")

		if request.WantReply {
			var response []byte
			switch payload := payload.(type) {
			case *tcpipRequestPayload:
				if payload.Port == 0 {
					response = ssh.Marshal(struct{ port uint32 }{uint32(rand.Intn(65536-1024) + 1024)})
				}
			}
			if err := request.Reply(accept, response); err != nil {
				log.Println("Failed to reply to channel request:", err)
				continue
			}
		}
	}
}

func createHostkeysRequestPayload(keys []ssh.Signer) []byte {
	result := make([]byte, 0)
	for _, key := range keys {
		result = append(result, ssh.Marshal(struct{ key string }{string(key.PublicKey().Marshal())})...)
	}
	return result
}
