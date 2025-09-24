// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package godebug provides a minimal stub implementation for the drsa package.
package godebug

// Setting represents a single GODEBUG setting.
type Setting struct {
	name string
	value string
}

// New creates a new Setting.
func New(name string) *Setting {
	return &Setting{name: name}
}

// Value returns the current value of the setting.
func (s *Setting) Value() string {
	// For the rsa1024min setting, return empty string by default
	// which means RSA keys must be at least 1024 bits
	return s.value
}

// IncNonDefault records that a non-default value was used.
func (s *Setting) IncNonDefault() {
	// Stub implementation - do nothing for now
}