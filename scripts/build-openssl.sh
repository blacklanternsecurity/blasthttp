#!/usr/bin/env bash
# Build OpenSSL from source with weak cipher support enabled.
# Supports cross-compilation via CARGO_BUILD_TARGET env var.
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
OPENSSL_SHA256="2e8a40b01979afe8be0bbfb3de5dc1c6709fedb46d6c89c10da114ab5fc3d281"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENDOR_DIR="${PROJECT_ROOT}/vendor/openssl"
SOURCE_DIR="${VENDOR_DIR}/openssl-${OPENSSL_VERSION}"
INSTALL_DIR="${VENDOR_DIR}/install"
TARBALL="${VENDOR_DIR}/openssl-${OPENSSL_VERSION}.tar.gz"
MARKER="${INSTALL_DIR}/.blasthttp-built"

# --- Cross-compilation support ---
TARGET="${CARGO_BUILD_TARGET:-}"

# Map Rust target triple to OpenSSL ./Configure target
openssl_target=""
case "$TARGET" in
    aarch64-unknown-linux-gnu*|aarch64-unknown-linux-musl*)
        openssl_target="linux-aarch64" ;;
    armv7-unknown-linux-gnueabihf|armv7-unknown-linux-musleabihf)
        openssl_target="linux-armv4" ;;
    i686-unknown-linux-gnu*|i686-unknown-linux-musl*)
        openssl_target="linux-x86" ;;
    s390x-unknown-linux-gnu*)
        openssl_target="linux64-s390x" ;;
    powerpc64le-unknown-linux-gnu*)
        openssl_target="linux-ppc64le" ;;
    x86_64-*|"")
        ;; # native — use ./config auto-detection
    *)
        echo "WARNING: Unknown target '$TARGET', falling back to native build"
        ;;
esac

# Skip if already built for the same target
if [ -f "$MARKER" ]; then
    BUILT_TARGET=$(cat "$MARKER" 2>/dev/null || true)
    if [ "$BUILT_TARGET" = "$TARGET" ]; then
        echo "=== OpenSSL ${OPENSSL_VERSION} already built for '${TARGET:-native}' at ${INSTALL_DIR} ==="
        echo "=== Delete ${INSTALL_DIR} to force rebuild ==="
        exit 0
    fi
    echo "=== Rebuilding OpenSSL: target changed from '${BUILT_TARGET:-native}' to '${TARGET:-native}' ==="
    rm -rf "$INSTALL_DIR"
fi

echo "=== Building OpenSSL ${OPENSSL_VERSION} with weak cipher support ==="
if [ -n "$openssl_target" ]; then
    echo "=== Cross-compiling for: $openssl_target (Rust target: $TARGET) ==="
fi

mkdir -p "$VENDOR_DIR"

# Download
if [ ! -f "$TARBALL" ]; then
    echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
    curl -L -f -o "$TARBALL" "$OPENSSL_URL" || wget -O "$TARBALL" "$OPENSSL_URL"
fi

# Verify SHA256
echo "Verifying checksum..."
ACTUAL_SHA256=$(sha256sum "$TARBALL" | awk '{print $1}')
if [ "$ACTUAL_SHA256" != "$OPENSSL_SHA256" ]; then
    echo "ERROR: SHA256 mismatch!"
    echo "  Expected: ${OPENSSL_SHA256}"
    echo "  Got:      ${ACTUAL_SHA256}"
    rm -f "$TARBALL"
    exit 1
fi

# Extract
if [ -d "$SOURCE_DIR" ]; then
    rm -rf "$SOURCE_DIR"
fi
echo "Extracting..."
tar xzf "$TARBALL" -C "$VENDOR_DIR"

# --- Find cross-compiler if needed ---
find_cross_cc() {
    local target="$1"

    # Check target-specific CC_<target> env var (set by maturin cross containers)
    local target_env="${target//-/_}"
    local cc_var="CC_${target_env}"
    if [ -n "${!cc_var:-}" ]; then
        echo "${!cc_var}"
        return 0
    fi

    # Check generic CC (if it looks like a cross-compiler, not just "gcc")
    if [ -n "${CC:-}" ] && [[ "$CC" == *-gcc ]] ; then
        echo "$CC"
        return 0
    fi

    # Try common cross-compiler names
    local candidates=()
    case "$target" in
        aarch64-unknown-linux-gnu*)
            candidates=(aarch64-linux-gnu-gcc aarch64-unknown-linux-gnu-gcc) ;;
        aarch64-unknown-linux-musl*)
            candidates=(aarch64-linux-musl-gcc aarch64-alpine-linux-musl-gcc aarch64-unknown-linux-musl-gcc) ;;
        armv7-unknown-linux-gnueabihf)
            candidates=(arm-linux-gnueabihf-gcc armv7-unknown-linux-gnueabihf-gcc) ;;
        armv7-unknown-linux-musleabihf)
            candidates=(arm-linux-musleabihf-gcc armv7-alpine-linux-musleabihf-gcc armv7-unknown-linux-musleabihf-gcc) ;;
        i686-unknown-linux-gnu*)
            candidates=(i686-linux-gnu-gcc i686-unknown-linux-gnu-gcc i386-linux-gnu-gcc) ;;
        i686-unknown-linux-musl*)
            candidates=(i686-linux-musl-gcc i686-alpine-linux-musl-gcc i686-unknown-linux-musl-gcc) ;;
        s390x-unknown-linux-gnu*)
            candidates=(s390x-linux-gnu-gcc s390x-ibm-linux-gnu-gcc s390x-unknown-linux-gnu-gcc) ;;
        powerpc64le-unknown-linux-gnu*)
            candidates=(powerpc64le-linux-gnu-gcc powerpc64le-unknown-linux-gnu-gcc) ;;
    esac

    for cc in "${candidates[@]}"; do
        if command -v "$cc" >/dev/null 2>&1; then
            echo "$cc"
            return 0
        fi
    done

    # Final fallback: use plain gcc (may work if container already targets the right arch)
    echo "gcc"
    return 0
}

# Configure
cd "$SOURCE_DIR"

COMMON_ARGS=(
    --prefix="$INSTALL_DIR"
    enable-weak-ssl-ciphers
    enable-ssl3
    no-shared
    no-module
    no-tests
    -fPIC
)

if [ -n "$openssl_target" ]; then
    CROSS_CC=$(find_cross_cc "$TARGET")
    echo "Configuring with: ./Configure $openssl_target (CC=$CROSS_CC)"

    # s390x cross-assembler may lack newer instructions (e.g. cijne) — disable asm
    EXTRA_ARGS=()
    case "$TARGET" in
        s390x-*) EXTRA_ARGS+=(no-asm) ;;
    esac

    # Derive --cross-compile-prefix from CC name (e.g. aarch64-linux-gnu-gcc -> aarch64-linux-gnu-)
    if [[ "$CROSS_CC" == *-gcc ]]; then
        cross_compile_prefix="${CROSS_CC%-gcc}-"
        ./Configure "$openssl_target" "${COMMON_ARGS[@]}" "${EXTRA_ARGS[@]}" --cross-compile-prefix="$cross_compile_prefix"
    else
        CC="$CROSS_CC" ./Configure "$openssl_target" "${COMMON_ARGS[@]}" "${EXTRA_ARGS[@]}"
    fi
else
    echo "Configuring with: ./config (native auto-detect)"
    ./config "${COMMON_ARGS[@]}"
fi

# Build
NUM_JOBS=$(nproc 2>/dev/null || echo 4)
echo "Building with ${NUM_JOBS} jobs..."
make -j"$NUM_JOBS"

# Install (skip docs)
echo "Installing..."
make install_sw

# Mark as complete (store target for cache invalidation)
mkdir -p "$INSTALL_DIR"
echo "$TARGET" > "$MARKER"

echo ""
echo "=== OpenSSL ${OPENSSL_VERSION} built successfully ==="
echo "=== Install location: ${INSTALL_DIR} ==="
echo "=== Now run: cargo build ==="
