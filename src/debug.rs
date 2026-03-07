/// Print a debug message to stderr if verbosity >= required level.
/// Level 1 (-v):   request/response flow, headers, decompression
/// Level 2 (-vv):  TLS details (future)
/// Level 3 (-vvv): raw bytes, full dumps (future)
pub fn debug_print(verbosity: u8, level: u8, msg: &str) {
    if verbosity >= level {
        eprintln!("[blasthttp] {}", msg);
    }
}
