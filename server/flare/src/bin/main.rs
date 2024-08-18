#[tokio::main]
async fn main() {
    let path = std::env::current_dir().unwrap();
    flare::launch(path).await.unwrap();
}
