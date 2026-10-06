#!/bin/bash
mkdir -p build

SDK=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null || echo "")

if [ -z "$SDK" ]; then
    echo "Xcode SDK not found. Ensure Xcode command line tools are installed."
    exit 1
fi

clang -dynamiclib \
    -arch arm64 \
    -isysroot "$SDK" \
    -miphoneos-version-min=12.0 \
    -Isrc -Ivendor \
    -framework Foundation \
    -framework Security \
    -fobjc-arc \
    vendor/fishhook.c \
    src/IPRedirector.m \
    -o build/libIPRedirector.dylib

echo "Build successful: build/libIPRedirector.dylib"
