pub mod api;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod logging;
pub mod macros;
pub mod store;
pub mod tasks;
pub mod time;

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

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, server.port));
    let handle = Handle::new();

    tokio::spawn(graceful_shutdown(handle.clone()));

    tracing::info!("Setup done, binding to port {:?}...", server.port);
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
    .await?;

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

    tracing::info!("Shutting down...");
    handle.graceful_shutdown(Some(Duration::from_secs(30)));
}
