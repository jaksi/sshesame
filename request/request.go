package request

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
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

func Handle(remoteAddr net.Addr, channel string, requests <-chan *ssh.Request) {
	for request := range requests {
		var payload string
		switch request.Type {
		case "tcpip-forward":
			fallthrough
		case "cancel-tcpip-forward":
			parsedPayload := tcpipForward{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		case "pty-req":
			parsedPayload := pty{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		case "x11-req":
			parsedPayload := x11{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		case "env":
			parsedPayload := env{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		case "exec":
			parsedPayload := exec{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		case "subsystem":
			parsedPayload := subsystem{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		case "window-change":
			parsedPayload := windowChange{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		case "xon-xoff":
			parsedPayload := flowControl{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		case "signal":
			parsedPayload := signal{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		case "exit-status":
			parsedPayload := exitStatus{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		case "exit-signal":
			parsedPayload := exitSignal{}
			err := ssh.Unmarshal(request.Payload, &parsedPayload)
			if err != nil {
				log.Println("Failed to parse payload:", err.Error())
				payload = fmt.Sprintf("%v", request.Payload)
			} else {
				payload = fmt.Sprintf("%+v", parsedPayload)
			}
		default:
			payload = fmt.Sprintf("%v", request.Payload)
		}
		log.Printf("Request: client=%v, channel=%v, type=%v, payload=%v\n", remoteAddr, channel, request.Type, payload)
		if request.WantReply {
			request.Reply(true, nil)
		}
	}
}
