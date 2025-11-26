use flare::config;
use tempfile::TempDir;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    tracing::info!("Parsing config...");

    let storage = TempDir::new().unwrap();
    let external = TempDir::new().unwrap();
    let mut config = config::config("config.example");
    config.store.storage.base_path = storage.path().to_path_buf();
    config.server.mtls_external = external.path().to_path_buf();

    flare::launch(config).await.unwrap();
}
