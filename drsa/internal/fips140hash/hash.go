// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fips140hash

import (
	fsha3 "github.com/jaekwon/openpgp/drsa/internal/fips140/sha3"
	"crypto/sha3"
	"hash"
	_ "unsafe"
)

// sha3Unwrap implementation for drsa fork
func sha3Unwrap(h *sha3.SHA3) *fsha3.Digest {
	// This is a stub implementation for the drsa fork
	// In practice, we'd need to extract the internal digest
	// For now, return nil as we don't use SHA3 in RSA
	return nil
}

// Unwrap returns h, or a crypto/internal/fips140 inner implementation of h.
//
// The return value can be type asserted to one of
// [crypto/internal/fips140/sha256.Digest],
// [crypto/internal/fips140/sha512.Digest], or
// [crypto/internal/fips140/sha3.Digest] if it is a FIPS 140-3 approved hash.
func Unwrap(h hash.Hash) hash.Hash {
	if sha3, ok := h.(*sha3.SHA3); ok {
		return sha3Unwrap(sha3)
	}
	return h
}

// UnwrapNew returns a function that calls newHash and applies [Unwrap] to the
// return value.
func UnwrapNew[Hash hash.Hash](newHash func() Hash) func() hash.Hash {
	return func() hash.Hash { return Unwrap(newHash()) }
}
