# drsa - Deterministic RSA

A fork of Go's crypto/rsa package modified to support deterministic key generation.

## Features

- Fully deterministic RSA key generation when using a deterministic random source
- Removes all calls to `randutil.MaybeReadByte` 
- Includes deterministic prime generation
- Compatible with standard crypto/rsa types through conversion functions

## Usage

```go
import (
    "bytes"
    "github.com/jaekwon/openpgp/drsa"
)

// Create a deterministic private key from fixed entropy
entropy := []byte("your-fixed-entropy-source-here-should-be-long-enough")
reader := bytes.NewReader(entropy)

// Generate a deterministic 2048-bit RSA key
privateKey, err := drsa.GenerateKey(reader, 2048)
if err != nil {
    panic(err)
}

// The same entropy will always generate the same key
reader2 := bytes.NewReader(entropy)
privateKey2, err := drsa.GenerateKey(reader2, 2048)
if err != nil {
    panic(err)
}

// privateKey and privateKey2 will be identical

// Convert between drsa and crypto/rsa types for x509 compatibility:
cryptoKey := drsa.ToCryptoRSA(privateKey)
drsaKey := drsa.FromCryptoRSA(cryptoPrivateKey)
```
