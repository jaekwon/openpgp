package main

// this is a test, i will replace this with custom entropy.

import (
	"io"
	"time"
	"bufio"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"fmt"
	"os"
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
	t := (len(x)+len(y)-1) / len(y)
	for i:=0; i<t; i++ {
		xi := b256{}
		xs := len(y)*i
		xe := min(len(y)*(i+1), len(x))
		copy(xi[:], x[xs:xe])
		y = xor(y, xi)
	}
	return y
}

func xor(a, b b256) (c b256) {
	for i := 0; i<len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

// Any hash function may have restricted range of output, so we XOR the
// original every time, which could increase the range of output.
// XXX test.
func next256(ent b256, last b256) (next b256) {
	h := sha256.New()
	x := xor(ent, last)
	h.Write(x[:])
	s := h.Sum(nil)
	copy(next[:], s)
	fmt.Printf("ent %X last %X xor %X hash %X\n", ent, last, x, s)
	return
}

func test() {
	fmt.Println(min(1,2))
	fmt.Println(min(2,1))
	fmt.Println(fold256([]byte("a")))
	fmt.Println(fold256([]byte("abc")))
	fmt.Println(fold256([]byte("1234567890")))
	fmt.Println(fold256([]byte("12345678901234567890123456789012")))
	fmt.Println(fold256([]byte("123456789012345678901234567890122")))
	fmt.Println(fold256([]byte("1234567890123456789012345678901212345678901234567890123456789012")))
	fmt.Println(fold256([]byte("12345678901234567890123456789012123456789012345678901234567890121")))
	{
	fmt.Println("----------------------------------------")
	a := b256{}
	b := b256{}
	fmt.Println(next256(a, b))
	fmt.Println(next256(a, b))
	b = next256(a, b)
	fmt.Println(next256(a, b))
	}

	{
	fmt.Println("----------------------------------------")
	a := b256{}
	a[0] = 0xFF
	b := b256{}
	fmt.Println(next256(a, b))
	fmt.Println(next256(a, b))
	b = next256(a, b)
	fmt.Println(next256(a, b))
	}
}

func main() {
	test()

	// The only entropy source is user input, and deterministic.
	reader := bufio.NewReader(os.Stdin)
	size, _ := reader.ReadString('\n')
	sz, err := strconv.Atoi(size[:len(size)-1])
	if err != nil {
		panic(err)
	}
	fmt.Println("size:", sz)
	text, _ := reader.ReadString('\n')
	fmt.Println("read:", text)

	// Run goroutine for writing pseudo-random bytes from entropy.
	reader2, writer := io.Pipe()
	written := 0
	go func() {
		ent := fold256([]byte(text))
		last := b256{}
		next := next256(ent, last)
		for {
			writer.Write(next[:])
			written += len(next)
			fmt.Printf("writing to writer: %X (%d)\n", next, written)
			time.Sleep(time.Millisecond)
			next = next256(ent, next)
		}
	}()


	// Generate key using above source of random bytes...
	fmt.Println("generating key")

	privateKey, err := rsa.GenerateKey(reader2, sz)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating RSA key: %s", err)
		return
	}

	fmt.Println("generated key")

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
