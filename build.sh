#!/bin/bash

# Exit on error
set -e

APP_NAME="mini-proxy"
SRC_FILE="mini-proxy.go"
OUT_FILE="${APP_NAME}"

# Try to find a working go binary
if [ -x "/usr/local/go/bin/go" ]; then
    GO_BIN="/usr/local/go/bin/go"
elif command -v go &> /dev/null; then
    GO_BIN=$(command -v go)
else
    echo "Error: go is not installed. Please install Go to build this project."
    exit 1
fi

# Check for windows parameter
if [[ "$1" == "--windows" || "$1" == "windows" ]]; then
    echo "Targeting Windows (amd64)..."
    export GOOS=windows
    export GOARCH=amd64
    OUT_FILE="${APP_NAME}.exe"
fi

echo "Building ${OUT_FILE}..."
echo "Using go from: $GO_BIN"

# Build the application
"$GO_BIN" build -o "${OUT_FILE}" .

# Success message
echo "Build successful: ./${OUT_FILE}"
if [ "$GOOS" != "windows" ]; then
    chmod +x "${OUT_FILE}"
fi
