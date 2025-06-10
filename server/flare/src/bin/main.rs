use flare::config;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    tracing::info!("Starting up...");

    let config = config::config();
    flare::launch(config).await.unwrap();
}
