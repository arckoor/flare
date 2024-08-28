pub mod api;
mod auth;
pub mod config;
mod crypto;
mod db;
mod macros;
#[allow(warnings, unused)]
mod prisma;
mod store;

use std::{
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
};

use config::FlareConfig;
use tower_http::trace::{DefaultOnFailure, DefaultOnRequest, DefaultOnResponse};
use tracing::Level;

pub async fn launch(config: FlareConfig) -> Result<(), std::io::Error> {
    let FlareConfig { store, server } = config;

    let state = Arc::new(store::Store::new(store).await);
    let router = api::routes::build_router(state);
    let router = router.layer(
        tower_http::trace::TraceLayer::new_for_http()
            .on_request(DefaultOnRequest::new().level(Level::INFO))
            .on_response(DefaultOnResponse::new().level(Level::INFO))
            .on_failure(DefaultOnFailure::new().level(Level::ERROR)),
    );

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, server.port));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);
    axum::serve(listener, router)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}
