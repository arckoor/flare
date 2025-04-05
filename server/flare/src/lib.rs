pub mod api;
pub mod auth;
pub mod config;
mod crypto;
mod db;
mod logging;
mod macros;
mod store;
mod util;

use std::{
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
};

use config::FlareConfig;

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
    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
    .await
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    // Todo graceful shutdown

    Ok(())
}
