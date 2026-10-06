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
PATCH_DIR="${SCRIPT_DIR}/openssl-patches"

# The features that make this build different from a stock OpenSSL.
#
# `enable-ssl3` and `enable-ssl3-method` both have to be here. OpenSSL's
# Configure has a disable cascade that reads "if ssl3-method is off, turn ssl3
# off too", and ssl3-method is off by default. So enable-ssl3 on its own gets
# cascaded straight back to no-ssl3, which is exactly what happened here for
# a long time: the flag was passed, configdata.pm recorded both `enable-ssl3`
# and `no-ssl3`, and the build came out with OPENSSL_NO_SSL3 defined and no
# SSLv3_method symbols.
FEATURE_FLAGS=(
    enable-weak-ssl-ciphers
    enable-ssl3
    enable-ssl3-method
    no-shared
    no-module
    no-tests
    -fPIC
)


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

# Identifies what the cached build actually is. Both the target and the
# feature flags belong in here: an existing checkout whose flags changed needs
# a rebuild just as much as one whose target changed, and keying on the target
# alone means a flag change is silently ignored until someone deletes the
# install directory by hand.
# Patches are part of the recipe too: editing one has to invalidate the cached
# build exactly as changing a flag does, or the change silently does nothing.
PATCH_HASH="none"
if [ -d "$PATCH_DIR" ] && compgen -G "$PATCH_DIR/*.patch" > /dev/null; then
    PATCH_HASH=$(cat "$PATCH_DIR"/*.patch | sha256sum | cut -c1-16)
fi
BUILD_RECIPE="${TARGET:-native}|${OPENSSL_VERSION}|${FEATURE_FLAGS[*]}|patches=${PATCH_HASH}"

# Skip only if the cached build was made the same way
if [ -f "$MARKER" ]; then
    BUILT_RECIPE=$(cat "$MARKER" 2>/dev/null || true)
    if [ "$BUILT_RECIPE" = "$BUILD_RECIPE" ]; then
        echo "=== OpenSSL ${OPENSSL_VERSION} already built for '${TARGET:-native}' at ${INSTALL_DIR} ==="
        echo "=== Delete ${INSTALL_DIR} to force rebuild ==="
        exit 0
    fi
    echo "=== Rebuilding OpenSSL: build recipe changed ==="
    echo "===   was: ${BUILT_RECIPE:-(unknown)}"
    echo "===   now: ${BUILD_RECIPE}"
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

# --- Apply our patches ---
#
# Applied to a freshly extracted tree every time, so the patches never stack
# and a failure is always a real conflict rather than a second application.
# Every patch is required: a silent skip would produce a build that looks fine
# and behaves differently, which is the failure mode that hid the SSLv3
# problem for months.
if [ -d "$PATCH_DIR" ]; then
    for patch in "$PATCH_DIR"/*.patch; do
        [ -e "$patch" ] || continue
        echo "Applying $(basename "$patch")"
        if ! patch -p1 -d "$SOURCE_DIR" -s < "$patch"; then
            echo "ERROR: failed to apply $(basename "$patch")" >&2
            echo "The patch probably needs rebasing onto OpenSSL ${OPENSSL_VERSION}." >&2
            exit 1
        fi
    done
fi

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
    "${FEATURE_FLAGS[@]}"
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

# Mark as complete (store the full recipe so a flag or target change invalidates)
mkdir -p "$INSTALL_DIR"
echo "$BUILD_RECIPE" > "$MARKER"

echo ""
echo "=== OpenSSL ${OPENSSL_VERSION} built successfully ==="
echo "=== Install location: ${INSTALL_DIR} ==="
echo "=== Now run: cargo build ==="
