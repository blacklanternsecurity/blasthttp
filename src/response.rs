use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub url: String,
    pub status: u16,
    // Vec, not HashMap — HTTP allows duplicate header names (e.g. Set-Cookie)
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing)]
    pub body_bytes: Vec<u8>,
    pub body: String,
    pub elapsed_ms: u64,
    pub redirect_chain: Vec<RedirectHop>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub url: String,
    pub status: u16,
}
