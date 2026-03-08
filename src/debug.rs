use std::sync::{Arc, Mutex};

/// Collects debug messages during a request.
/// Shared across async functions via Arc<Mutex<>>.
pub type DebugLog = Arc<Mutex<Vec<String>>>;

/// Create a new empty debug log.
pub fn new_debug_log() -> DebugLog {
    Arc::new(Mutex::new(Vec::new()))
}

/// Record a debug message.
/// - Always appends to the log collector (for Python to consume).
/// - Also prints to stderr when verbosity >= level (for CLI).
pub fn debug_record(log: &DebugLog, verbosity: u8, level: u8, msg: &str) {
    if let Ok(mut messages) = log.lock() {
        messages.push(msg.to_string());
    }
    if verbosity >= level {
        eprintln!("[blasthttp] {}", msg);
    }
}
