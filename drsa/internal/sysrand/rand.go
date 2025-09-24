// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sysrand provides system random number generation.
package sysrand

import (
	"crypto/rand"
	"io"
)

// Read fills b with cryptographically secure random bytes.
func Read(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)
	return err
}