use crate::config::RequestConfig;
use crate::response::Response;
use super::{HttpClient, ClientError};

pub struct MockClient {
    status: u16,
    body: String,
    error: Option<String>,
}

impl MockClient {
    pub fn new(status: u16, body: String) -> Self {
        MockClient { status, body, error: None }
    }

    pub fn with_error(message: String) -> Self {
        MockClient { status: 0, body: String::new(), error: Some(message) }
    }
}

impl HttpClient for MockClient {
    async fn send(&self, config: &RequestConfig) -> Result<Response, ClientError> {
        if let Some(ref msg) = self.error {
            return Err(ClientError { message: msg.clone() });
        }

        Ok(Response {
            url: config.url.clone(),
            status: self.status,
            headers: Vec::new(),
            body_bytes: self.body.as_bytes().to_vec(),
            body: self.body.clone(),
            elapsed_ms: 0,
            redirect_chain: Vec::new(),
        })
    }
}
