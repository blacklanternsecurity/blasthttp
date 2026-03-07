use blasthttp::config::RequestConfig;
use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use clap::Parser;

#[derive(Parser)]
#[command(name = "blasthttp", about = "Offensive-first HTTP client")]
struct Cli {
    /// Target URL
    url: String,

    /// Enable TLS certificate validation (off by default)
    #[arg(long)]
    verify_certs: bool,

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

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let mut config = RequestConfig::new(cli.url);
    config.verify_certs = Some(cli.verify_certs);
    config.follow_redirects = Some(cli.follow_redirects);
    config.max_redirects = Some(cli.max_redirects);
    config.timeout_seconds = cli.timeout;
    config.max_body_size = cli.max_body_size;
    config.verbosity = cli.verbose;

    let client = HyperClient::new();

    match client.send(&config).await {
        Ok(response) => {
            match serde_json::to_string_pretty(&response) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error serializing response: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
