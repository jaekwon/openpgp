#!/bin/bash

# To download a specific Go version:
# go install golang.org/dl/go1.25.1@latest && go1.25.1 download

set -e

echo "Generating diff between drsa and Go's crypto/rsa"

GO_CRYPTO=$(go env GOROOT)/src/crypto

if [ ! -d "$GO_CRYPTO/rsa" ]; then
    echo "Error: Go source not found at $GO_CRYPTO/rsa"
    exit 1
fi

OUT_DIR="upstream-diff"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "Generating diffs..."

for file in $(find . -name "*.go" -type f | grep -v "^\./upstream-diff" | sed 's|^\./||'); do
    # Map drsa paths to crypto paths
    if [[ "$file" == internal/* ]]; then
        go_file="$GO_CRYPTO/$file"
    else
        go_file="$GO_CRYPTO/rsa/$file"
    fi
    
    mkdir -p "$OUT_DIR/$(dirname "$file")"
    
    if [ -f "$go_file" ]; then
        diff -u "$go_file" "$file" > "$OUT_DIR/$file.diff" || true
        echo "  M $file"
    else
        diff -u /dev/null "$file" > "$OUT_DIR/$file.diff" || true
        echo "  A $file"
    fi
done

find "$OUT_DIR" -name "*.diff" -type f -exec cat {} \; > "$OUT_DIR/combined.diff" 2>/dev/null || true

echo
echo "✓ Done! Diffs saved to $OUT_DIR/"