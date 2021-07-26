package main

import (
	"bytes"
	"log"
	"testing"
)

func setupLogBuffer(t *testing.T, cfg *config) *bytes.Buffer {
	if err := cfg.setupLogging(); err != nil {
		t.Fatalf("Failed to setup logging: %v", err)
	}
	buffer := &bytes.Buffer{}
	log.SetOutput(buffer)
	return buffer
}
