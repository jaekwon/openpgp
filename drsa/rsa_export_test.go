// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package drsa

import "os"

func init() {
	// Allow small RSA keys for testing
	os.Setenv("GODEBUG", "rsa1024min=0")
}

var NonZeroRandomBytes = nonZeroRandomBytes
