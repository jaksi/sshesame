package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

type logEntry interface {
	fmt.Stringer
	eventType() string
}

type authAccepted bool

func (accepted authAccepted) String() string {
	if accepted {
		return "accepted"
	}
	return "rejected"
}

type authLog struct {
	User     string       `json:"user"`
	Accepted authAccepted `json:"accepted"`
}

type noAuthLog struct {
	authLog
}

func (entry noAuthLog) String() string {
	return fmt.Sprintf("authentication for user %q without credentials %v", entry.User, entry.Accepted)
}
func (entry noAuthLog) eventType() string {
	return "no_auth"
}

type passwordAuthLog struct {
	authLog
	Password string `json:"password"`
}

func (entry passwordAuthLog) String() string {
	return fmt.Sprintf("authentication for user %q with password %q %v", entry.User, entry.Password, entry.Accepted)
}
func (entry passwordAuthLog) eventType() string {
	return "password_auth"
}

type publicKeyAuthLog struct {
	authLog
	PublicKeyFingerprint string `json:"public_key"`
}

func (entry publicKeyAuthLog) String() string {
	return fmt.Sprintf("authentication for user %q with public key %q %v", entry.User, entry.PublicKeyFingerprint, entry.Accepted)
}
func (entry publicKeyAuthLog) eventType() string {
	return "public_key_auth"
}

type keyboardInteractiveAuthLog struct {
	authLog
	Answers []string `json:"answers"`
}

func (entry keyboardInteractiveAuthLog) String() string {
	return fmt.Sprintf("authentication for user %q with keyboard interactive answers %q %v", entry.User, entry.Answers, entry.Accepted)
}
func (entry keyboardInteractiveAuthLog) eventType() string {
	return "keyboard_interactive_auth"
}

type connectionLog struct {
	ClientVersion string `json:"client_version"`
}

func (entry connectionLog) String() string {
	return fmt.Sprintf("connection with client version %q established", entry.ClientVersion)
}
func (entry connectionLog) eventType() string {
	return "connection"
}

type connectionCloseLog struct {
}

func (entry connectionCloseLog) String() string {
	return "connection closed"
}
func (entry connectionCloseLog) eventType() string {
	return "connection_close"
}

type tcpipForwardLog struct {
	Address string `json:"address"`
}

func (entry tcpipForwardLog) String() string {
	return fmt.Sprintf("TCP/IP forwarding on %v requested", entry.Address)
}
func (entry tcpipForwardLog) eventType() string {
	return "tcpip_forward"
}

type cancelTCPIPForwardLog struct {
	Address string `json:"address"`
}

func (entry cancelTCPIPForwardLog) String() string {
	return fmt.Sprintf("TCP/IP forwarding on %v canceled", entry.Address)
}
func (entry cancelTCPIPForwardLog) eventType() string {
	return "cancel_tcpip_forward"
}

type channelLog struct {
	ChannelID int `json:"channel_id"`
}

type sessionLog struct {
	channelLog
}

func (entry sessionLog) String() string {
	return fmt.Sprintf("[channel %v] session requested", entry.ChannelID)
}
func (entry sessionLog) eventType() string {
	return "session"
}

type sessionCloseLog struct {
	channelLog
}

func (entry sessionCloseLog) String() string {
	return fmt.Sprintf("[channel %v] closed", entry.ChannelID)
}
func (entry sessionCloseLog) eventType() string {
	return "session_close"
}

type sessionInputLog struct {
	channelLog
	Input string `json:"input"`
}

func (entry sessionInputLog) String() string {
	return fmt.Sprintf("[channel %v] input: %q", entry.ChannelID, entry.Input)
}
func (entry sessionInputLog) eventType() string {
	return "session_input"
}

type directTCPIPLog struct {
	channelLog
	From string `json:"from"`
	To   string `json:"to"`
}

func (entry directTCPIPLog) String() string {
	return fmt.Sprintf("[channel %v] direct TCP/IP forwarding from %v to %v requested", entry.ChannelID, entry.From, entry.To)
}
func (entry directTCPIPLog) eventType() string {
	return "direct_tcpip"
}

type directTCPIPCloseLog struct {
	channelLog
}

func (entry directTCPIPCloseLog) String() string {
	return fmt.Sprintf("[channel %v] closed", entry.ChannelID)
}
func (entry directTCPIPCloseLog) eventType() string {
	return "direct_tcpip_close"
}

type directTCPIPInputLog struct {
	channelLog
	Input string `json:"input"`
}

func (entry directTCPIPInputLog) String() string {
	return fmt.Sprintf("[channel %v] input: %q", entry.ChannelID, entry.Input)
}
func (entry directTCPIPInputLog) eventType() string {
	return "direct_tcpip_input"
}

type ptyLog struct {
	channelLog
	Terminal string `json:"terminal"`
	Width    uint32 `json:"width"`
	Height   uint32 `json:"height"`
}

func (entry ptyLog) String() string {
	return fmt.Sprintf("[channel %v] PTY using terminal %q (size %vx%v) requested", entry.ChannelID, entry.Terminal, entry.Width, entry.Height)
}
func (entry ptyLog) eventType() string {
	return "pty"
}

type shellLog struct {
	channelLog
}

func (entry shellLog) String() string {
	return fmt.Sprintf("[channel %v] shell requested", entry.ChannelID)
}
func (entry shellLog) eventType() string {
	return "shell"
}

type execLog struct {
	channelLog
	Command string `json:"command"`
}

func (entry execLog) String() string {
	return fmt.Sprintf("[channel %v] command %q requested", entry.ChannelID, entry.Command)
}
func (entry execLog) eventType() string {
	return "exec"
}

type subsystemLog struct {
	channelLog
	Subsystem string `json:"subsystem"`
}

func (entry subsystemLog) String() string {
	return fmt.Sprintf("[channel %v] subsystem %q requested", entry.ChannelID, entry.Subsystem)
}
func (entry subsystemLog) eventType() string {
	return "subsystem"
}

type x11Log struct {
	channelLog
	Screen uint32 `json:"screen"`
}

func (entry x11Log) String() string {
	return fmt.Sprintf("[channel %v] X11 forwarding on screen %v requested", entry.ChannelID, entry.Screen)
}
func (entry x11Log) eventType() string {
	return "x11"
}

type envLog struct {
	channelLog
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (entry envLog) String() string {
	return fmt.Sprintf("[channel %v] environment variable %q with value %q requested", entry.ChannelID, entry.Name, entry.Value)
}
func (entry envLog) eventType() string {
	return "env"
}

type windowChangeLog struct {
	channelLog
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
}

func (entry windowChangeLog) String() string {
	return fmt.Sprintf("[channel %v] window size change to %vx%v requested", entry.ChannelID, entry.Width, entry.Height)
}
func (entry windowChangeLog) eventType() string {
	return "window_change"
}

func (metadata connMetadata) logEvent(entry logEntry) {
	if metadata.cfg.Logging.JSON {
		logBytes, err := json.Marshal(struct {
			Time      string   `json:"time"`
			Source    string   `json:"source"`
			EventType string   `json:"event_type"`
			Event     logEntry `json:"event"`
		}{time.Now().Format(time.RFC3339), metadata.RemoteAddr().String(), entry.eventType(), entry})
		if err != nil {
			warningLogger.Printf("Failed to log event: %v", err)
			return
		}
		log.Print(string(logBytes))
	} else {
		log.Printf("[%v] %v", metadata.RemoteAddr().String(), entry)
	}
}
