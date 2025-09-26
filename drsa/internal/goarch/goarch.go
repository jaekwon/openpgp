// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package goarch provides architecture constants.
package goarch

import "runtime"

const BigEndian = false // Assume little-endian for now

// These need to be vars instead of consts since they depend on runtime
var (
	IsAmd64   = 0
	IsArm64   = 0
	IsPpc64   = 0
	IsPpc64le = 0
)

func init() {
	switch runtime.GOARCH {
	case "amd64":
		IsAmd64 = 1
	case "arm64":
		IsArm64 = 1
	case "ppc64":
		IsPpc64 = 1
	case "ppc64le":
		IsPpc64le = 1
	}
}