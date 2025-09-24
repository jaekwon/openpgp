// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stringslite provides string operations.
package stringslite

import "strings"

// HasPrefix tests whether the string s begins with prefix.
func HasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

// TrimPrefix returns s without the provided leading prefix string.
func TrimPrefix(s, prefix string) string {
	return strings.TrimPrefix(s, prefix)
}