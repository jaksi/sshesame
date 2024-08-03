package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
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

// Static keys, only used in tests, to speed them up by not having to generate new keys every time.
const (
	testRSAKey = `-----BEGIN PRIVATE KEY-----
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
qtfwiyotqKKmXeyJWEqJ56B7lw==
-----END PRIVATE KEY-----`
	testECDSAKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcPlksxvJRBMC7H70
xGOaGRgody4vm36E2Zm8/UbyVMShRANCAATaM4DFbeUO0JFkUTlUPIhhD9II3391
bdnZwRL5hG1CZw7oVWsCfgm3ujpToKFqAz22AVQees07AV9cICpx+i21
-----END PRIVATE KEY-----`
	testEd25519Key = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIpRrU9cXkMb3/c/H1oAAQpnnS6PXrWJe1jvYo6pSxNw
-----END PRIVATE KEY-----`
)

func writeTestKeys(t *testing.T, dataDir string) {
	for fileName, content := range map[string]string{
		"host_rsa_key":     testRSAKey,
		"host_ecdsa_key":   testECDSAKey,
		"host_ed25519_key": testEd25519Key,
	} {
		if err := os.WriteFile(filepath.Join(dataDir, fileName), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
