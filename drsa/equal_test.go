// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package drsa_test

import (
	"crypto"
	"crypto/rsa"
	. "github.com/jaekwon/openpgp/drsa"
	"crypto/x509"
	"testing"
)

func TestEqual(t *testing.T) {
	t.Setenv("GODEBUG", "rsa1024min=0") // Allow 512-bit keys for testing

	private := test512Key
	public := &private.PublicKey

	if !public.Equal(public) {
		t.Errorf("public key is not equal to itself: %v", public)
	}
	if !public.Equal(crypto.Signer(private).Public().(*PublicKey)) {
		t.Errorf("private.Public() is not Equal to public: %q", public)
	}
	if !private.Equal(private) {
		t.Errorf("private key is not equal to itself: %v", private)
	}

	enc, err := x509.MarshalPKCS8PrivateKey(ToCryptoRSA(private))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := x509.ParsePKCS8PrivateKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	rsaDecoded := decoded.(*rsa.PrivateKey)
	if !public.Equal(&PublicKey{N: rsaDecoded.N, E: rsaDecoded.E}) {
		t.Errorf("public key is not equal to itself after decoding: %v", public)
	}
	if !private.Equal(FromCryptoRSA(decoded.(*rsa.PrivateKey))) {
		t.Errorf("private key is not equal to itself after decoding: %v", private)
	}

	other := test512KeyTwo
	if public.Equal(other.Public()) {
		t.Errorf("different public keys are Equal")
	}
	if private.Equal(other) {
		t.Errorf("different private keys are Equal")
	}
}
