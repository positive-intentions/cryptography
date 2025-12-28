#!/bin/bash

echo "Building Signal Protocol WASM..."

# Copy the wasm_exec.js support file from Go installation
if [ -z "$GOROOT" ]; then
    echo "GOROOT not set, trying to find Go installation..."
    GOROOT=$(go env GOROOT)
fi

if [ -f "$GOROOT/misc/wasm/wasm_exec.js" ]; then
    cp "$GOROOT/misc/wasm/wasm_exec.js" .
    echo "✓ Copied wasm_exec.js"
else
    echo "⚠ Could not find wasm_exec.js. You may need to copy it manually from your Go installation."
    echo "  Usually located at: \$GOROOT/misc/wasm/wasm_exec.js"
fi

# Build the WASM binary
echo "Building WASM binary..."
GOOS=js GOARCH=wasm go build -o signal.wasm .

if [ $? -eq 0 ]; then
    echo "✓ Build successful!"
    echo ""
    echo "Files created:"
    ls -lh signal.wasm 2>/dev/null
    echo ""
    echo "To test the WASM module:"
    echo "1. Start a local web server: python3 -m http.server 8080"
    echo "2. Open http://localhost:8080/index.html in your browser"
else
    echo "✗ Build failed!"
    exit 1
fi