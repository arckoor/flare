pub mod api;
pub mod auth;
pub mod config;
mod crypto;
mod db;
mod logging;
mod macros;
mod store;

use std::{
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum_server::Handle;
use config::FlareConfig;
use tokio::signal;

pub async fn launch(config: FlareConfig) -> Result<(), std::io::Error> {
    let FlareConfig { store, server } = config;

    let state = Arc::new(store::Store::new(store).await);
    let router = {
        let router = api::routes::build_router(state);
        logging::setup_tracing(router)
    };

    // todo we probably don't want to log sqlx in production
    #[cfg(not(feature = "sim"))]
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, server.port));
    let handle = Handle::new();

    tokio::spawn(graceful_shutdown(handle.clone()));

    {
        #[cfg(not(feature = "sim"))]
        {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .expect("Failed to install TLS provider");
            let config = crypto::mtls::create_tls_config(&server.cert_path);
            axum_server::bind_rustls(addr, config)
        }
        #[cfg(feature = "sim")]
        axum_server::bind(addr)
    }
    .handle(handle)
    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
    .await
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(())
}

async fn graceful_shutdown(handle: Handle) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Received shutdown signal, shutting down gracefully...");
    handle.graceful_shutdown(Some(Duration::from_secs(30)));
}
