use flare::config;

#[tokio::main]
async fn main() {
    let config = config::config();
    flare::launch(config).await.unwrap();
}
