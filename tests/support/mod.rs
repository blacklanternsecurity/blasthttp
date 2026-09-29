// Shared helpers for the integration tests.
//
// These live under `tests/support/` rather than directly in `tests/` because
// Cargo compiles every top-level file there as its own test binary. A helper
// module sitting at that level becomes a test target with no tests in it, and
// one that fails to build on its own the moment it references a sibling.
//
// Not every test uses every helper, so the modules allow dead code rather than
// making each consumer carry an allow attribute.

#![allow(dead_code)]

pub mod antibot;
pub mod ja4;
pub mod tls_server;
