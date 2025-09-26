// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package godebug provides a minimal stub implementation for the drsa package.
package godebug

import (
	"os"
	"strings"
)

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
	// Parse GODEBUG environment variable on every call
	// This ensures we pick up settings from TestMain/init
	godebug := os.Getenv("GODEBUG")
	for _, pair := range strings.Split(godebug, ",") {
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 && parts[0] == s.name {
			return parts[1]
		}
	}
	return ""
}

// IncNonDefault records that a non-default value was used.
func (s *Setting) IncNonDefault() {
	// Stub implementation - do nothing for now
}