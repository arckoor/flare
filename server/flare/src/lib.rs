pub mod api;
mod auth;
mod db;
#[allow(warnings, unused)]
mod prisma;
mod store;
mod types;

use std::{
    net::{Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use store::Store;
use tower_http::trace::{DefaultOnFailure, DefaultOnRequest, DefaultOnResponse};
use tracing::Level;

pub async fn launch(working_dir: PathBuf) -> Result<(), std::io::Error> {
    let state = Arc::new(Store::new(working_dir).await);
    let router = api::routes::build_router(state);
    let router = router.layer(
        tower_http::trace::TraceLayer::new_for_http()
            .on_request(DefaultOnRequest::new().level(Level::INFO))
            .on_response(DefaultOnResponse::new().level(Level::INFO))
            .on_failure(DefaultOnFailure::new().level(Level::ERROR)),
    );

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 8080));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);
    axum::serve(listener, router)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}
