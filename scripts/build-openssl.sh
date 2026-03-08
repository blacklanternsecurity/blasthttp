#!/usr/bin/env bash
# Build OpenSSL from source with weak cipher support enabled.
# Run this once before `cargo build`. The output is cached in vendor/openssl/.
#
# Usage: ./scripts/build-openssl.sh
#
# This builds OpenSSL with:
#   - enable-weak-ssl-ciphers: RC4, DES, export ciphers
#   - enable-ssl3: SSLv3 protocol support
#   - no-shared: static linking
#   - no-module: bake legacy provider into libcrypto (no runtime .so needed)
#   - -fPIC: position-independent code (needed for cdylib/Python)

set -euo pipefail

OPENSSL_VERSION="3.3.2"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENDOR_DIR="${PROJECT_ROOT}/vendor/openssl"
SOURCE_DIR="${VENDOR_DIR}/openssl-${OPENSSL_VERSION}"
INSTALL_DIR="${VENDOR_DIR}/install"
TARBALL="${VENDOR_DIR}/openssl-${OPENSSL_VERSION}.tar.gz"
MARKER="${INSTALL_DIR}/.blasthttp-built"

# Skip if already built
if [ -f "$MARKER" ]; then
    echo "=== OpenSSL ${OPENSSL_VERSION} already built at ${INSTALL_DIR} ==="
    echo "=== Delete ${INSTALL_DIR} to force rebuild ==="
    exit 0
fi

echo "=== Building OpenSSL ${OPENSSL_VERSION} with weak cipher support ==="

mkdir -p "$VENDOR_DIR"

# Download
if [ ! -f "$TARBALL" ]; then
    echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
    curl -L -f -o "$TARBALL" "$OPENSSL_URL" || wget -O "$TARBALL" "$OPENSSL_URL"
fi

# Extract
if [ -d "$SOURCE_DIR" ]; then
    rm -rf "$SOURCE_DIR"
fi
echo "Extracting..."
tar xzf "$TARBALL" -C "$VENDOR_DIR"

# Configure
echo "Configuring with weak cipher support..."
cd "$SOURCE_DIR"
./config \
    --prefix="$INSTALL_DIR" \
    enable-weak-ssl-ciphers \
    enable-ssl3 \
    no-shared \
    no-module \
    no-tests \
    -fPIC

# Build
NUM_JOBS=$(nproc 2>/dev/null || echo 4)
echo "Building with ${NUM_JOBS} jobs..."
make -j"$NUM_JOBS"

# Install (skip docs)
echo "Installing..."
make install_sw

# Mark as complete
touch "$MARKER"

echo ""
echo "=== OpenSSL ${OPENSSL_VERSION} built successfully ==="
echo "=== Install location: ${INSTALL_DIR} ==="
echo "=== Now run: cargo build ==="
