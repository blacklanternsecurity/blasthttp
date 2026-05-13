use blasthttp::batch;
use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use blasthttp::response::Response;
use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "blasthttp", about = "Offensive-first HTTP client")]
struct Cli {
    /// Target URL (omit when using -l)
    url: Option<String>,

    /// HTTP method
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,

    /// Custom header (repeatable: -H "Name: Value")
    #[arg(short = 'H', long = "header", num_args = 1)]
    headers: Vec<String>,

    /// Request body
    #[arg(short, long)]
    data: Option<String>,

    /// File containing URLs (one per line)
    #[arg(short = 'l', long = "list")]
    file: Option<String>,

    /// Maximum concurrent requests in batch mode
    #[arg(short = 'c', long, default_value = "50")]
    concurrency: usize,

    /// Rate limit in requests per second (batch mode; unlimited by default)
    #[arg(long = "rate-limit")]
    rate_limit: Option<f64>,

    /// Enable TLS certificate validation (off by default)
    #[arg(long)]
    verify: bool,

    /// Maximum response body size in bytes
    #[arg(long)]
    max_body_size: Option<usize>,

    /// Follow redirects
    #[arg(short = 'L', long)]
    follow_redirects: bool,

    /// Maximum number of redirects to follow
    #[arg(long, default_value = "10")]
    max_redirects: u32,

    /// Request timeout in seconds
    #[arg(short, long)]
    timeout: Option<u64>,

    /// HTTP/SOCKS proxy URL (e.g. http://127.0.0.1:8080, socks5://...)
    #[arg(short = 'x', long)]
    proxy: Option<String>,

    /// OpenSSL cipher string (e.g. "ALL", "HIGH", "RC4-SHA")
    #[arg(long)]
    ciphers: Option<String>,

    /// Minimum TLS version (1.0, 1.1, 1.2, 1.3)
    #[arg(long)]
    min_tls: Option<String>,

    /// Maximum TLS version (1.0, 1.1, 1.2, 1.3)
    #[arg(long)]
    max_tls: Option<String>,

    /// Verbosity: -v pretty print + debug, -vv includes body
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn serialize_response(resp: &Response, verbose: u8) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(resp)?;
    if verbose < 2 {
        value.as_object_mut().map(|obj| obj.remove("body"));
    }
    if verbose >= 1 {
        serde_json::to_string_pretty(&value)
    } else {
        serde_json::to_string(&value)
    }
}

fn parse_header(s: &str) -> Option<(String, String)> {
    let (name, value) = s.split_once(':')?;
    Some((name.trim().to_string(), value.trim().to_string()))
}

fn build_config(cli: &Cli, url: String) -> RequestConfig {
    let mut config = RequestConfig::new(url);
    config.method = Some(cli.method.clone());

    if !cli.headers.is_empty() {
        config.headers = Some(cli.headers.iter().filter_map(|h| parse_header(h)).collect());
    }

    config.body = cli.data.clone().map(String::into_bytes);
    config.verify_certs = Some(cli.verify);
    config.follow_redirects = Some(cli.follow_redirects);
    config.max_redirects = Some(cli.max_redirects);
    config.timeout_seconds = cli.timeout;
    config.max_body_size = cli.max_body_size;
    config.proxy = cli.proxy.clone();
    config.cipher_string = cli.ciphers.clone();
    config.min_tls_version = cli.min_tls.clone();
    config.max_tls_version = cli.max_tls.clone();
    config.verbosity = cli.verbose;
    config
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.url.is_none() && cli.file.is_none() {
        eprintln!("Error: provide a URL or use -f <file>");
        std::process::exit(1);
    }

    if let Some(ref file_path) = cli.file {
        run_batch(&cli, file_path).await;
    } else {
        run_single(&cli).await;
    }
}

async fn run_single(cli: &Cli) {
    let config = build_config(cli, cli.url.clone().unwrap());
    let client = HyperClient::new();

    match client.send(&config).await {
        Ok(response) => match serialize_response(&response, cli.verbose) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Error serializing response: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn run_batch(cli: &Cli, file_path: &str) {
    let content = match std::fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", file_path, e);
            std::process::exit(1);
        }
    };

    let urls: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if urls.is_empty() {
        eprintln!("No URLs found in {}", file_path);
        std::process::exit(1);
    }

    eprintln!(
        "Sending {} requests (concurrency: {})...",
        urls.len(),
        cli.concurrency
    );

    let configs: Vec<RequestConfig> = urls
        .iter()
        .map(|url| build_config(cli, url.to_string()))
        .collect();

    let client = Arc::new(HyperClient::new());
    let results = batch::send_batch(client, configs, cli.concurrency, cli.rate_limit, None).await;

    for r in results {
        match r.result {
            Ok(resp) => {
                if let Ok(json) = serialize_response(&resp, cli.verbose) {
                    println!("{}", json);
                }
            }
            Err(e) => eprintln!("Error [{}]: {}", r.url, e),
        }
    }
}
