// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package impl provides implementation selection.
package impl

// Available indicates if a specific implementation is available
func Available(name string) bool {
	// Stub implementation - always return false for now
	return false
}

// Register registers an implementation
func Register(name string, impl string, available *bool) {
	// Stub implementation - do nothing for now
}