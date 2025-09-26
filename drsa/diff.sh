#!/bin/bash

# To download a specific Go version:
# go install golang.org/dl/go1.25.1@latest && go1.25.1 download

set -e

echo "Generating diff between drsa and Go's crypto/rsa"

GO_RSA=$(go env GOROOT)/src/crypto/rsa
GO_CRYPTO=$(go env GOROOT)/src/crypto

if [ ! -d "$GO_RSA" ]; then
    echo "Error: Go source not found at $GO_RSA"
    exit 1
fi

OUT_DIR="upstream-diff"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "Generating diffs..."

# Files in root directory (crypto/rsa)
for file in *.go; do
    if [ -f "$GO_RSA/$file" ]; then
        diff -u "$GO_RSA/$file" "$file" > "$OUT_DIR/$file.diff" || true
        echo "  M $file"
    else
        diff -u /dev/null "$file" > "$OUT_DIR/$file.diff" || true
        echo "  A $file"
    fi
done

# Internal packages (map internal/ to crypto/internal/)
for file in $(find internal -name "*.go" -type f); do
    go_file="$GO_CRYPTO/$file"
    if [ -f "$go_file" ]; then
        mkdir -p "$OUT_DIR/$(dirname "$file")"
        diff -u "$go_file" "$file" > "$OUT_DIR/$file.diff" || true
        echo "  M $file"
    else
        mkdir -p "$OUT_DIR/$(dirname "$file")"
        diff -u /dev/null "$file" > "$OUT_DIR/$file.diff" || true
        echo "  A $file"
    fi
done

find "$OUT_DIR" -name "*.diff" -type f -exec cat {} \; > "$OUT_DIR/combined.diff" 2>/dev/null || true

echo
echo "✓ Done! Diffs saved to $OUT_DIR/"