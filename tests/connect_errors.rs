//! A connect failure should say why it failed, on both the pooled path and the
//! direct one. hyper-util's own error reads "client error (Connect)" whatever
//! the cause, so these check that the cause underneath makes it out.

use blasthttp::client::hyper::HyperClient;
use blasthttp::client::{ErrorKind, HttpClient};
use blasthttp::config::RequestConfig;
use tokio::net::TcpListener;

/// A local port with nothing listening on it.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

fn config_for(url: String) -> RequestConfig {
    let mut config = RequestConfig::new(url);
    config.timeout_seconds = Some(5);
    config.retries = Some(0);
    config
}

#[tokio::test]
async fn test_refused_connection_says_so_on_the_pooled_path() {
    let port = closed_port().await;
    let config = config_for(format!("http://127.0.0.1:{}/", port));

    let err = HyperClient::new().send(&config).await.unwrap_err();

    assert_eq!(err.kind, ErrorKind::Connection);
    assert!(
        err.message.to_lowercase().contains("refused"),
        "message should give the cause: {}",
        err.message
    );
}

#[tokio::test]
async fn test_refused_connection_says_so_on_the_direct_path() {
    let port = closed_port().await;
    let mut config = config_for(format!("http://localhost:{}/", port));
    // resolve_ip sends the request down the direct path
    config.resolve_ip = Some("127.0.0.1".to_string());

    let err = HyperClient::new().send(&config).await.unwrap_err();

    assert_eq!(err.kind, ErrorKind::Connection);
    assert!(
        err.message.to_lowercase().contains("refused"),
        "message should give the cause: {}",
        err.message
    );
}
