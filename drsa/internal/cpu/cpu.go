// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cpu provides minimal CPU feature detection.
package cpu

// Options contains detected CPU features.
type Options struct {
	HasAES       bool
	HasADX       bool
	HasAVX       bool
	HasAVX2      bool
	HasBMI2      bool
	HasPCLMULQDQ bool
	HasSHA       bool
	HasSSE41     bool
	HasSSSE3     bool
	HasPMULL     bool
	HasSHA2      bool
	HasSHA512    bool
	HasSHA3      bool
	HasLSX       bool
	HasLASX      bool
	HasAESCBC    bool
	HasAESCTR    bool
	HasAESGCM    bool
	HasECDSA     bool
	HasGHASH     bool
	HasSHA256    bool
}

var (
	// Default to false for all features in this stub implementation
	ARM64  Options
	Loong64 Options
	S390X  Options
	X86    Options
)