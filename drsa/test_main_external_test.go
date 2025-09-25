package drsa_test

import (
	"os"
	"testing"
)

// TestMain sets up the test environment for drsa_test package
func TestMain(m *testing.M) {
	// Allow small RSA keys for testing
	os.Setenv("GODEBUG", "rsa1024min=0")
	
	// Run tests
	code := m.Run()
	os.Exit(code)
}