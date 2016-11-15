package request

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
)

// RFC 4254
type tcpipForward struct {
	BindAddress string
	BindPort    uint32
}

func (payload tcpipForward) String() string {
	return net.JoinHostPort(payload.BindAddress, strconv.Itoa(int(payload.BindPort)))
}

type pty struct {
	Term                    string
	Width, Height           uint32
	PixelWidth, PixelHeight uint32
	Modes                   []byte
}

func (payload pty) String() string {
	return fmt.Sprintf("%v, %vx%v (%vx%v pixels)", payload.Term, payload.Width, payload.Height, payload.PixelWidth, payload.PixelHeight)
}

type x11 struct {
	SingleConnection       bool
	AuthenticationProtocol string
	AuthenticationCookie   string
	Screen                 uint32
}

func (payload x11) String() string {
	return fmt.Sprintf("Single connection: %v, protocol: %v, cookie: %v, screen: %v", payload.SingleConnection, payload.AuthenticationProtocol, payload.AuthenticationCookie, payload.Screen)
}

type env struct {
	Name, Value string
}

func (payload env) String() string {
	return fmt.Sprintf("%v=%v", payload.Name, payload.Value)
}

type exec struct {
	Command string
}

func (payload exec) String() string {
	return payload.Command
}

type subsystem struct {
	Name string
}

func (payload subsystem) String() string {
	return payload.Name
}

type windowChange struct {
	Width, Height           uint32
	PixelWidth, PixelHeight uint32
}

func (payload windowChange) String() string {
	return fmt.Sprintf("%vx%v (%vx%v pixels)", payload.Width, payload.Height, payload.PixelWidth, payload.PixelHeight)
}

type flowControl struct {
	CanDo bool
}

func (payload flowControl) String() string {
	return strconv.FormatBool(payload.CanDo)
}

type signal struct {
	Name string
}

func (payload signal) String() string {
	return payload.Name
}

type exitStatus struct {
	Status uint32
}

func (payload exitStatus) String() string {
	return strconv.Itoa(int(payload.Status))
}

type exitSignal struct {
	Name         string
	CoreDumped   bool
	ErrorMessage string
	Language     string
}

func (payload exitSignal) String() string {
	return fmt.Sprintf("%v, core dumped: %v, error message: %v, language: %v", payload.Name, payload.CoreDumped, payload.ErrorMessage, payload.Language)
}

func SendExitStatus(channel ssh.Channel) {
	_, err := channel.SendRequest("exit-status", false, ssh.Marshal(exitStatus{0}))
	if err != nil {
		log.Warning("Failed to send exit status:", err.Error())
	}
}

func Handle(remoteAddr net.Addr, channel string, requests <-chan *ssh.Request) {
	for request := range requests {
		var payload interface{} = request.Payload
		switch request.Type {
		case "tcpip-forward":
			fallthrough
		case "cancel-tcpip-forward":
			parsedPayload := tcpipForward{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		case "pty-req":
			parsedPayload := pty{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		case "x11-req":
			parsedPayload := x11{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		case "env":
			parsedPayload := env{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		case "exec":
			parsedPayload := exec{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		case "subsystem":
			parsedPayload := subsystem{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		case "window-change":
			parsedPayload := windowChange{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		case "xon-xoff":
			parsedPayload := flowControl{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		case "signal":
			parsedPayload := signal{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		case "exit-status":
			parsedPayload := exitStatus{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		case "exit-signal":
			parsedPayload := exitSignal{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = parsedPayload
		}
		log.WithFields(log.Fields{
			"client":  remoteAddr,
			"channel": channel,
			"request": request.Type,
			"payload": payload,
		}).Info("Request received")
		if request.WantReply {
			err := request.Reply(true, nil)
			if err != nil {
				log.Warning("Failed to accept request:", err.Error())
				continue
			}
		}
	}
}
