package drsa

import (
	"os"
	"testing"
)

// TestMain sets up the test environment
func TestMain(m *testing.M) {
	// Allow small RSA keys for testing
	os.Setenv("GODEBUG", "rsa1024min=0")
	
	// Run tests
	code := m.Run()
	os.Exit(code)
}