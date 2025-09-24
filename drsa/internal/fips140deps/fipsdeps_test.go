// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fipsdeps

import (
	"internal/testenv"
	"strings"
	"testing"
)

// AllowedInternalPackages are internal packages that can be imported from the
// FIPS module. The API of these packages ends up locked for the lifetime of the
// validated module, which can be years.
//
// DO NOT add new packages here just to make the tests pass.
var AllowedInternalPackages = map[string]bool{
	// entropy.Depleted is the external passive entropy source, and sysrand.Read
	// is the actual (but uncredited!) random bytes source.
	"github.com/jaekwon/openpgp/drsa/internal/entropy": true,
	"github.com/jaekwon/openpgp/drsa/internal/sysrand": true,

	// impl.Register is how the packages expose their alternative
	// implementations to tests outside the module.
	"github.com/jaekwon/openpgp/drsa/internal/impl": true,

	// randutil.MaybeReadByte is used in non-FIPS mode by GenerateKey functions.
	"github.com/jaekwon/openpgp/drsa/internal/randutil": true,
}

func TestImports(t *testing.T) {
	cmd := testenv.Command(t, testenv.GoToolPath(t), "list", "-f", `{{$path := .ImportPath -}}
{{range .Imports -}}
{{$path}} {{.}}
{{end -}}
{{range .TestImports -}}
{{$path}} {{.}}
{{end -}}
{{range .XTestImports -}}
{{$path}} {{.}}
{{end -}}`, "github.com/jaekwon/openpgp/drsa/internal/fips140/...")
	bout, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, bout)
	}
	out := string(bout)

	// In a snapshot, all the paths are crypto/internal/fips140/v1.2.3/...
	// Determine the version number and remove it for the test.
	_, v, _ := strings.Cut(out, "github.com/jaekwon/openpgp/drsa/internal/fips140/")
	v, _, _ = strings.Cut(v, "/")
	v, _, _ = strings.Cut(v, " ")
	if strings.HasPrefix(v, "v") && strings.Count(v, ".") == 2 {
		out = strings.ReplaceAll(out, "github.com/jaekwon/openpgp/drsa/internal/fips140/"+v, "github.com/jaekwon/openpgp/drsa/internal/fips140")
	}

	allPackages := make(map[string]bool)

	// importCheck is the set of packages that import crypto/internal/fips140/check.
	importCheck := make(map[string]bool)

	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		pkg, importedPkg, _ := strings.Cut(line, " ")

		allPackages[pkg] = true

		if importedPkg == "github.com/jaekwon/openpgp/drsa/internal/fips140/check" {
			importCheck[pkg] = true
		}

		// Ensure we don't import any unexpected internal package from the FIPS
		// module, since we can't change the module source after it starts
		// validation. This locks in the API of otherwise internal packages.
		if importedPkg == "github.com/jaekwon/openpgp/drsa/internal/fips140" ||
			strings.HasPrefix(importedPkg, "github.com/jaekwon/openpgp/drsa/internal/fips140/") ||
			strings.HasPrefix(importedPkg, "github.com/jaekwon/openpgp/drsa/internal/fips140deps/") {
			continue
		}
		if AllowedInternalPackages[importedPkg] {
			continue
		}
		if strings.Contains(importedPkg, "internal") {
			t.Errorf("unexpected import of internal package: %s -> %s", pkg, importedPkg)
		}
	}

	// Ensure that all packages except check and check's dependencies import check.
	for pkg := range allPackages {
		switch pkg {
		case "github.com/jaekwon/openpgp/drsa/internal/fips140/check":
		case "github.com/jaekwon/openpgp/drsa/internal/fips140":
		case "github.com/jaekwon/openpgp/drsa/internal/fips140/alias":
		case "github.com/jaekwon/openpgp/drsa/internal/fips140/subtle":
		case "github.com/jaekwon/openpgp/drsa/internal/fips140/hmac":
		case "github.com/jaekwon/openpgp/drsa/internal/fips140/sha3":
		case "github.com/jaekwon/openpgp/drsa/internal/fips140/sha256":
		case "github.com/jaekwon/openpgp/drsa/internal/fips140/sha512":
		default:
			if !importCheck[pkg] {
				t.Errorf("package %s does not import crypto/internal/fips140/check", pkg)
			}
		}
	}
}
