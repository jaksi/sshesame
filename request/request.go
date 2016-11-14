package request

import (
	log "github.com/Sirupsen/logrus"
	"github.com/fatih/structs"
	"golang.org/x/crypto/ssh"
	"net"
)

// RFC 4254
type tcpipForward struct {
	BindAddress string
	BindPort    uint32
}
type pty struct {
	Term                    string
	Width, Height           uint32
	PixelWidth, PixelHeight uint32
	Modes                   []byte
}
type x11 struct {
	SingleConnection       bool
	AuthenticationProtocol string
	AuthenticationCookie   string
	Screen                 uint32
}
type env struct {
	Name, Value string
}
type exec struct {
	Command string
}
type subsystem struct {
	Name string
}
type windowChange struct {
	Width, Height           uint32
	PixelWidth, PixelHeight uint32
}
type flowControl struct {
	CanDo bool
}
type signal struct {
	Name string
}
type exitStatus struct {
	Status uint32
}
type exitSignal struct {
	Name         string
	CoreDumped   bool
	ErrorMessage string
	Language     string
}

func SendExitStatus(channel ssh.Channel) {
	_, err := channel.SendRequest("exit-status", false, ssh.Marshal(exitStatus{0}))
	if err != nil {
		log.Warning("Failed to send exit status:", err.Error())
	}
}

func Handle(remoteAddr net.Addr, channel string, requests <-chan *ssh.Request) {
	for request := range requests {
		payload := map[string]interface{}{
			"data": request.Payload,
		}
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
			payload = structs.Map(parsedPayload)
		case "pty-req":
			parsedPayload := pty{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = structs.Map(parsedPayload)
		case "x11-req":
			parsedPayload := x11{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = structs.Map(parsedPayload)
		case "env":
			parsedPayload := env{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = structs.Map(parsedPayload)
		case "exec":
			parsedPayload := exec{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = structs.Map(parsedPayload)
		case "subsystem":
			parsedPayload := subsystem{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = structs.Map(parsedPayload)
		case "window-change":
			parsedPayload := windowChange{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = structs.Map(parsedPayload)
		case "xon-xoff":
			parsedPayload := flowControl{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = structs.Map(parsedPayload)
		case "signal":
			parsedPayload := signal{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = structs.Map(parsedPayload)
		case "exit-status":
			parsedPayload := exitStatus{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = structs.Map(parsedPayload)
		case "exit-signal":
			parsedPayload := exitSignal{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Warning("Failed to parse payload:", err.Error())
				break
			}
			payload = structs.Map(parsedPayload)
		}
		logData := payload
		logData["client"] = remoteAddr
		logData["channel"] = channel
		logData["request"] = request.Type
		log.WithFields(logData).Info("Request received")
		if request.WantReply {
			err := request.Reply(true, nil)
			if err != nil {
				log.Warning("Failed to accept request:", err.Error())
				continue
			}
		}
	}
}
