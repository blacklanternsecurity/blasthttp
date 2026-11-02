# Sourced by maturin-action inside the manylinux and musllinux containers.
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache perl make gcc musl-dev linux-headers curl bash
elif command -v yum >/dev/null 2>&1; then
  yum install -y perl-core
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update && apt-get install -y perl make gcc curl
fi
./scripts/build-openssl.sh
OPENSSL_DIR="$(pwd)/vendor/openssl/install"
export OPENSSL_DIR OPENSSL_STATIC=1 OPENSSL_NO_VENDOR=1
# openssl-sys reads <TARGET>_OPENSSL_DIR, which the cross images preset, before OPENSSL_DIR.
for var in $(env | grep '_OPENSSL_DIR=' | cut -d= -f1); do
  export "$var=$OPENSSL_DIR"
done
