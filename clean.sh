#!/bin/bash

APP_NAME="mini-proxy"

echo "Cleaning binaries..."

if [ -f "${APP_NAME}" ]; then
    rm "${APP_NAME}"
    echo "Removed ${APP_NAME}"
fi

if [ -f "${APP_NAME}.exe" ]; then
    rm "${APP_NAME}.exe"
    echo "Removed ${APP_NAME}.exe"
fi

echo "Clean finished."
