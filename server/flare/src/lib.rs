pub mod api;
mod auth;
pub mod config;
mod crypto;
mod db;
mod macros;
#[allow(warnings, unused)]
mod prisma;
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
    let router = api::routes::build_router(state);
    #[cfg(debug_assertions)]
    let router = {
        use std::time::Duration;
        let router = router.layer(
            tower_http::trace::TraceLayer::new_for_http()
                .on_request(|req: &hyper::Request<_>, _: &tracing::Span| {
                    let long_uri = req.uri();
                    let uri = if long_uri
                        .query()
                        .is_some_and(|q| q.to_string().contains("code="))
                    {
                        long_uri.path()
                    } else {
                        &long_uri.to_string()
                    };
                    tracing::info!(
                        method = %req.method(),
                        path = %uri,
                        "started processing request"
                    )
                })
                .on_response(
                    |res: &hyper::Response<_>, latency: Duration, _span: &tracing::Span| {
                        tracing::info!(
                            status = %res.status(),
                            latency = ?latency,
                            "completed request"
                        )
                    },
                ),
        );
        #[cfg(not(feature = "sim"))]
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();

        router
    };
    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, server.port));

    #[cfg(not(feature = "sim"))]
    {
        let config = crypto::mtls::create_tls_config(&server.cert_path);

        axum_server::bind_rustls(addr, config)
            .serve(router.into_make_service())
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }
    #[cfg(feature = "sim")]
    {
        axum_server::bind(addr)
            .serve(router.into_make_service())
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }

    Ok(())
}
