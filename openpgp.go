package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

type b256 [32]byte

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

// x can be any length, but output is always 256 bits.
func fold256(x []byte) (y b256) {
	t := (len(x) + len(y) - 1) / len(y)
	for i := 0; i < t; i++ {
		xi := b256{}
		xs := len(y) * i
		xe := min(len(y)*(i+1), len(x))
		copy(xi[:], x[xs:xe])
		y = xor(y, xi)
	}
	return y
}

func xor(a, b b256) (c b256) {
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

// Any hash function may have restricted range of output, so we XOR the
// original every time, which could increase the range of output.
func next256(ent b256, last b256) (next b256) {
	h := sha256.New()
	x := xor(ent, last)
	h.Write(x[:])
	s := h.Sum(nil)
	copy(next[:], s)
	return
}

func main() {
	// Define flags
	keySize := flag.Int("bits", 8192, "RSA key size in bits (default: 8192)")
	entropy := flag.String("entropy", "", "Entropy string (dice rolls or card shuffle)")
	raw := flag.Bool("raw", false, "Treat entropy as raw string without format parsing")
	debug := flag.Bool("debug", false, "Show debug information about entropy processing")
	help := flag.Bool("help", false, "Show help message")
	
	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  D20 dice (42 rolls):\n")
		fmt.Fprintf(os.Stderr, "    %s -entropy \"4 2 20 15 8 12 3 19 7 11 16 5 14 9 1 18 10 6 13 17 20 8 15 3 11 7 19 2 14 5 16 12 9 4 1 18 6 10 13 17 20 7\"\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Card shuffle (52 cards):\n")
		fmt.Fprintf(os.Stderr, "    %s -entropy \"As 4d Jh Kc Td 9h 2s 7c Qd 3h 8s Ac 5d Kh 6c Js 10h 4s 9c Ad 2h 7d Qs 3c 8h Kd 5s Jc Ah 6d 10s 4h 9d 2c 7h Qc 3d 8c Ks 5h Jd As 6s 10c 4c 9s 2d 7s Qh 3s 8d 10d\"\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "SECURITY WARNING: In production, entropy should NEVER be passed as command-line\n")
		fmt.Fprintf(os.Stderr, "                  arguments as they are visible in process lists and shell history!\n\n")
	}
	
	flag.Parse()
	
	// Show help if requested
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	
	// Check if entropy was provided
	if *entropy == "" {
		fmt.Fprintf(os.Stderr, "ERROR: Missing entropy. Use -entropy flag to provide entropy string.\n\n")
		flag.Usage()
		os.Exit(1)
	}
	
	// Validate key size
	if *keySize < 1024 {
		fmt.Fprintf(os.Stderr, "ERROR: Key size must be at least 1024 bits\n")
		os.Exit(1)
	}
	
	sz := *keySize
	text := *entropy

	fmt.Println("================================================================================")
	fmt.Println("DEVELOPMENT MODE WARNING:")
	fmt.Println("- Entropy is being passed via command-line argument (INSECURE!)")
	fmt.Println("- This is ONLY for development/testing purposes")
	fmt.Println("- Production version will read entropy securely from stdin")
	fmt.Println("- Command-line arguments are visible in process lists and shell history!")
	fmt.Println("================================================================================")
	fmt.Println()

	fmt.Printf("Key size: %d bits\n", sz)
	
	// Parse entropy to detect format and convert to efficient representation
	parsedEntropy, err := parseEntropy(text, *raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nERROR: %s\n", err)
		fmt.Fprintf(os.Stderr, "\nThe entropy format was not recognized as:\n")
		fmt.Fprintf(os.Stderr, "  - D20 dice rolls (e.g., \"4 2 20 15 8...\")\n")
		fmt.Fprintf(os.Stderr, "  - Card shuffle (e.g., \"As 4d Jh Kc...\")\n")
		fmt.Fprintf(os.Stderr, "\nUse -raw flag to treat input as raw bytes without parsing.\n")
		os.Exit(1)
	}
	
	// Show format detection result
	switch parsedEntropy.Type {
	case EntropyTypeDice:
		fmt.Println("Entropy format: D20 dice rolls")
	case EntropyTypeCards:
		fmt.Println("Entropy format: Card shuffle")
	case EntropyTypeRaw:
		fmt.Println("Entropy format: Raw bytes (no parsing)")
	}
	
	if *debug {
		fmt.Printf("Entropy: %s\n", text)
		fmt.Println()
		debugPrintParsedEntropy(parsedEntropy)
		fmt.Println()

		// Show fold256 processing
		fmt.Println("DEBUG: === fold256 Processing ===")
		fmt.Printf("DEBUG: Folding %d bytes into 32 bytes\n", len(parsedEntropy.ParsedData))
		
		// Show chunk breakdown
		chunkSize := 32
		numChunks := (len(parsedEntropy.ParsedData) + chunkSize - 1) / chunkSize
		fmt.Printf("DEBUG: Number of 32-byte chunks: %d\n", numChunks)
		
		for i := 0; i < numChunks; i++ {
			start := i * chunkSize
			end := min((i+1)*chunkSize, len(parsedEntropy.ParsedData))
			chunk := parsedEntropy.ParsedData[start:end]
			fmt.Printf("DEBUG: Chunk %d (bytes %d-%d): %x\n", i, start, end-1, chunk)
		}
	}
	
	ent := fold256(parsedEntropy.ParsedData)
	
	if *debug {
		fmt.Printf("DEBUG: fold256 result: %x\n", ent)
		fmt.Println()

		// Show next256 processing
		fmt.Println("DEBUG: === next256 PRNG Processing ===")
		fmt.Printf("DEBUG: Initial entropy (ent): %x\n", ent)
	}
	
	// Run goroutine for writing pseudo-random bytes from entropy.
	reader2, writer := io.Pipe()
	written := 0
	go func() {
		last := b256{}
		if *debug {
			fmt.Printf("DEBUG: Initial last value: %x\n", last)
		}
		
		// First iteration details
		next := next256(ent, last)
		if *debug {
			fmt.Printf("DEBUG: First next256 call:\n")
			fmt.Printf("DEBUG:   ent XOR last = %x\n", xor(ent, last))
			fmt.Printf("DEBUG:   SHA256 result = %x\n", next)
		}
		
		iteration := 0
		for {
			writer.Write(next[:])
			written += len(next)
			iteration++
			
			// Only show debug for first few iterations
			if *debug && iteration <= 3 {
				fmt.Printf("DEBUG: Iteration %d: wrote %d bytes, total: %d\n", iteration, len(next), written)
			}
			
			time.Sleep(time.Millisecond)
			next = next256(ent, next)
		}
	}()

	// Generate key using above source of random bytes...
	if *debug {
		fmt.Println()
		fmt.Println("DEBUG: === RSA Key Generation ===")
		fmt.Printf("DEBUG: Generating %d-bit RSA key...\n", sz)
	} else {
		fmt.Println("Generating RSA key...")
	}

	privateKey, err := rsa.GenerateKey(reader2, sz)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating RSA key: %s", err)
		return
	}

	if *debug {
		fmt.Println("DEBUG: RSA key generation complete")
		fmt.Printf("DEBUG: Public key modulus (first 32 bytes): %x...\n", privateKey.N.Bytes()[:32])
		fmt.Println()
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling RSA private key: %s", err)
		return
	}

	fmt.Printf("%s", pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
}
