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

func testLogging(t *testing.T, cfg *loggingConfig, log logEntry, expectedLogs *regexp.Regexp) {
	t.Helper()
	c := &config{
		Logging: *cfg,
	}
	logBuffer := setupLogBuffer(t, c)
	connContext{ConnMetadata: mockConnContext{}, cfg: c}.logEvent(log)
	logs := logBuffer.String()
	// Remove trailing newline
	logs = logs[:len(logs)-1]
	if !expectedLogs.MatchString(logs) {
		t.Errorf("logs=%v, want match for %v", logs, expectedLogs)
	}
}

func TestPlainWithTimestamps(t *testing.T) {
	testLogging(t, &loggingConfig{
		JSON:       false,
		Timestamps: true,
	}, mockLogEntry{"lorem"}, regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[127\.0\.0\.1:1234\] test lorem$`))
}

func TestJSONWithTimestamps(t *testing.T) {
	testLogging(t, &loggingConfig{
		JSON:       true,
		Timestamps: true,
	}, mockLogEntry{"ipsum"}, regexp.MustCompile(`^{"time":"[^"]+","source":"127\.0\.0\.1:1234","event_type":"test","event":{"content":"ipsum"}}$`))
}

func TestPlainWithoutTimestamps(t *testing.T) {
	testLogging(t, &loggingConfig{
		JSON:       false,
		Timestamps: false,
	}, mockLogEntry{"dolor"}, regexp.MustCompile(`^\[127\.0\.0\.1:1234\] test dolor$`))
}

func TestJSONWithoutTimestamps(t *testing.T) {
	testLogging(t, &loggingConfig{
		JSON:       true,
		Timestamps: false,
	}, mockLogEntry{"sit"}, regexp.MustCompile(`^{"source":"127\.0\.0\.1:1234","event_type":"test","event":{"content":"sit"}}$`))
}

func TestPlainWithAddressSplitting(t *testing.T) {
	testLogging(t, &loggingConfig{
		JSON:          false,
		SplitHostPort: true,
	}, mockLogEntry{"amet"}, regexp.MustCompile(`^\[127\.0\.0\.1:1234\] test amet$`))
}

func TestJSONWithAddressSplitting(t *testing.T) {
	testLogging(t, &loggingConfig{
		JSON:          true,
		SplitHostPort: true,
	}, mockLogEntry{"consectetur"}, regexp.MustCompile(`^{"source":{"host":"127\.0\.0\.1","port":1234},"event_type":"test","event":{"content":"consectetur"}}$`))
}

func TestPlainWithoutAddressSplitting(t *testing.T) {
	testLogging(t, &loggingConfig{
		JSON:          false,
		SplitHostPort: false,
	}, mockLogEntry{"adipiscing"}, regexp.MustCompile(`^\[127\.0\.0\.1:1234\] test adipiscing$`))
}

func TestJSONWithoutAddressSplitting(t *testing.T) {
	testLogging(t, &loggingConfig{
		JSON:          true,
		SplitHostPort: false,
	}, mockLogEntry{"elit"}, regexp.MustCompile(`^{"source":"127\.0\.0\.1:1234","event_type":"test","event":{"content":"elit"}}$`))
}
