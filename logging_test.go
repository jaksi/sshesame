package main

import (
	"fmt"
	"regexp"
	"testing"
)

type mockLogEntry struct {
	Content string `json:"content"`
}

func (entry mockLogEntry) String() string {
	return fmt.Sprintf("test %v", entry.Content)
}

func (mockLogEntry) eventType() string {
	return "test"
}

func TestPlainWithTimestamps(t *testing.T) {
	cfg := &config{
		Logging: loggingConfig{
			JSON:       false,
			Timestamps: true,
		},
	}
	logBuffer := setupLogBuffer(t, cfg)
	connContext{ConnMetadata: mockConnContext{}, cfg: cfg}.logEvent(mockLogEntry{"lorem"})
	logs := logBuffer.String()
	expectedLogs := regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[127\.0\.0\.1:1234\] test lorem
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", logs, expectedLogs)
	}
}

func TestJSONWithTimestamps(t *testing.T) {
	cfg := &config{
		Logging: loggingConfig{
			JSON:       true,
			Timestamps: true,
		},
	}
	logBuffer := setupLogBuffer(t, cfg)
	connContext{ConnMetadata: mockConnContext{}, cfg: cfg}.logEvent(mockLogEntry{"ipsum"})
	logs := logBuffer.String()
	expectedLogs := regexp.MustCompile(`^{"time":"[^"]+","source":"127\.0\.0\.1:1234","event_type":"test","event":{"content":"ipsum"}}
$`)
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", logs, expectedLogs)
	}
}

func TestPlainWithoutTimestamps(t *testing.T) {
	cfg := &config{
		Logging: loggingConfig{
			JSON:       false,
			Timestamps: false,
		},
	}
	logBuffer := setupLogBuffer(t, cfg)
	connContext{ConnMetadata: mockConnContext{}, cfg: cfg}.logEvent(mockLogEntry{"dolor"})
	logs := logBuffer.String()
	expectedLogs := `[127.0.0.1:1234] test dolor
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}

func TestJSONWithoutTimestamps(t *testing.T) {
	cfg := &config{
		Logging: loggingConfig{
			JSON:       true,
			Timestamps: false,
		},
	}
	logBuffer := setupLogBuffer(t, cfg)
	connContext{ConnMetadata: mockConnContext{}, cfg: cfg}.logEvent(mockLogEntry{"sit"})
	logs := logBuffer.String()
	expectedLogs := `{"source":"127.0.0.1:1234","event_type":"test","event":{"content":"sit"}}
`
	if logs != expectedLogs {
		t.Errorf("logs=%v, want %v", logs, expectedLogs)
	}
}
