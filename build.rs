// build.rs — Verifies that our custom OpenSSL build exists.
// The actual compilation happens via `scripts/build-openssl.sh` (run once before cargo build).
// openssl-sys finds the custom build via env vars in .cargo/config.toml.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Check that the custom OpenSSL was built
    let openssl_dir = std::env::var("OPENSSL_DIR").unwrap_or_default();
    if openssl_dir.is_empty() {
        return; // No custom OpenSSL configured, using system default
    }

    let path = std::path::Path::new(&openssl_dir);
    if !path.join("include").join("openssl").join("ssl.h").exists() {
        panic!(
            "\n\n\
            ========================================================\n\
            Custom OpenSSL not found at: {}\n\
            Run `scripts/build-openssl.sh` first to build OpenSSL\n\
            with weak cipher support enabled.\n\
            ========================================================\n\n",
            openssl_dir
        );
    }
}
