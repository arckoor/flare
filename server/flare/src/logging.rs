use axum::Router;
use std::time::Duration;

use crate::api::services::extract_ip;

pub fn setup_tracing(router: Router) -> Router {
    let trace_layer = tower_http::trace::TraceLayer::new_for_http()
        .make_span_with(|req: &hyper::Request<_>| {
            tracing::info_span!(
                "http_request",
                method = %req.method(),
                path = %req.uri().path(),
                ip = extract_ip(req),
                id = %cuid2::create_id(),
            )
        })
        .on_request(|_req: &hyper::Request<_>, span: &tracing::Span| {
            let _enter = span.enter();
            tracing::info!("started request");
        })
        .on_response(
            |res: &hyper::Response<_>, latency: Duration, span: &tracing::Span| {
                let _enter = span.enter();
                tracing::info!(
                    status = %res.status(),
                    latency = ?latency,
                    "completed request"
                );
            },
        )
        .on_failure(|_, _, _: &tracing::Span| {});

    router.layer(trace_layer)
}
