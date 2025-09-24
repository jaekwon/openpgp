package drsa_test // XXX: modified for determinism

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/jaekwon/openpgp/drsa"
)

// deterministicReader provides deterministic "random" bytes for testing
type deterministicReader struct {
	seed  []byte
	state []byte
}

func newDeterministicReader(seed []byte) *deterministicReader {
	return &deterministicReader{
		seed:  seed,
		state: make([]byte, 32),
	}
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	for n < len(p) {
		// Generate next block using SHA256
		h := sha256.New()
		h.Write(r.seed)
		h.Write(r.state)
		r.state = h.Sum(nil)
		
		// Copy as much as we need
		copied := copy(p[n:], r.state)
		n += copied
	}
	return n, nil
}

// TestGenerateKeyDeterministic verifies that GenerateKey produces the same key
// when given the same random source
func TestGenerateKeyDeterministic(t *testing.T) {
	t.Run("1024-bit key", func(t *testing.T) {
		// Create two readers with same seed
		reader1 := newDeterministicReader([]byte("test seed for deterministic RSA"))
		reader2 := newDeterministicReader([]byte("test seed for deterministic RSA"))
		
		// Generate two keys
		key1, err := drsa.GenerateKey(reader1, 1024)
		if err != nil {
			t.Fatalf("Failed to generate first key: %v", err)
		}
		
		key2, err := drsa.GenerateKey(reader2, 1024)
		if err != nil {
			t.Fatalf("Failed to generate second key: %v", err)
		}
		
		// Compare public components
		if key1.N.Cmp(key2.N) != 0 {
			t.Errorf("Public modulus N differs between generations")
		}
		if key1.E != key2.E {
			t.Errorf("Public exponent E differs: %d vs %d", key1.E, key2.E)
		}
		
		// Compare private components
		if key1.D.Cmp(key2.D) != 0 {
			t.Errorf("Private exponent D differs between generations")
		}
		
		// Compare primes
		if len(key1.Primes) != len(key2.Primes) {
			t.Fatalf("Number of primes differs: %d vs %d", len(key1.Primes), len(key2.Primes))
		}
		for i := range key1.Primes {
			if key1.Primes[i].Cmp(key2.Primes[i]) != 0 {
				t.Errorf("Prime[%d] differs between generations", i)
			}
		}
		
		// Compare DER encoding using conversion to crypto/rsa
		rsaKey1 := drsa.ToCryptoRSA(key1)
		rsaKey2 := drsa.ToCryptoRSA(key2)
		
		der1, err := x509.MarshalPKCS8PrivateKey(rsaKey1)
		if err != nil {
			t.Fatalf("Failed to marshal first key: %v", err)
		}
		
		der2, err := x509.MarshalPKCS8PrivateKey(rsaKey2)
		if err != nil {
			t.Fatalf("Failed to marshal second key: %v", err)
		}
		
		if !bytes.Equal(der1, der2) {
			t.Errorf("DER encoding differs between keys")
		}
		
		t.Logf("Successfully generated deterministic %d-bit RSA key", 1024)
		t.Logf("Modulus (first 16 bytes): %x...", key1.N.Bytes()[:16])
	})
}

// TestGenerateKeyDifferentSeeds verifies that different random sources produce different keys
func TestGenerateKeyDifferentSeeds(t *testing.T) {
	reader1 := newDeterministicReader([]byte("seed one"))
	reader2 := newDeterministicReader([]byte("seed two"))
	
	key1, err := drsa.GenerateKey(reader1, 1024)
	if err != nil {
		t.Fatalf("Failed to generate first key: %v", err)
	}
	
	key2, err := drsa.GenerateKey(reader2, 1024)
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}
	
	// Keys should be different
	if key1.N.Cmp(key2.N) == 0 {
		t.Errorf("Different seeds produced same public modulus N")
	}
	if key1.D.Cmp(key2.D) == 0 {
		t.Errorf("Different seeds produced same private exponent D")
	}
}

// TestDeterministicReaderConsistency verifies the reader produces consistent output
func TestDeterministicReaderConsistency(t *testing.T) {
	seed := []byte("test seed")
	
	reader1 := newDeterministicReader(seed)
	reader2 := newDeterministicReader(seed)
	
	buf1 := make([]byte, 256)
	buf2 := make([]byte, 256)
	
	n1, err := reader1.Read(buf1)
	if err != nil {
		t.Fatalf("Failed to read from reader1: %v", err)
	}
	
	n2, err := reader2.Read(buf2)
	if err != nil {
		t.Fatalf("Failed to read from reader2: %v", err)
	}
	
	if n1 != n2 {
		t.Errorf("Read different amounts: %d vs %d", n1, n2)
	}
	
	if !bytes.Equal(buf1, buf2) {
		t.Errorf("Readers produced different output")
		t.Logf("buf1: %x", buf1[:32])
		t.Logf("buf2: %x", buf2[:32])
	}
}

