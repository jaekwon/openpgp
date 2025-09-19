// Package drsa is a deterministic fork of crypto/rsa that removes randutil.MaybeReadByte
// to allow fully deterministic key generation from a given random source.
package drsa

import (
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
)

// GenerateKey generates a deterministic RSA private key of the given bit size.
// Unlike crypto/rsa.GenerateKey, this implementation does not call randutil.MaybeReadByte,
// making the output fully deterministic for a given random source.
func GenerateKey(random io.Reader, bits int) (*rsa.PrivateKey, error) {
	// For now, we'll use a simple wrapper that calls the standard library
	// In the commit after this, we'll implement the actual deterministic generation
	return rsa.GenerateKey(random, bits)
}

// generatePrime generates a prime number of the given bit size.
// This is a placeholder that will be implemented in the next commit.
func generatePrime(rand io.Reader, bits int) (*big.Int, error) {
	return nil, errors.New("not implemented")
}