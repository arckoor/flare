use axum::Router;
use std::time::Duration;

pub fn setup_tracing(router: Router) -> Router {
    // todo this is meh :/
    let router = {
        let trace_layer = tower_http::trace::TraceLayer::new_for_http();
        #[cfg(debug_assertions)]
        let trace_layer = trace_layer
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
                |res: &hyper::Response<_>, latency: Duration, _: &tracing::Span| {
                    tracing::info!(
                        status = %res.status(),
                        latency = ?latency,
                        "completed request"
                    )
                },
            );

        router.layer(trace_layer)
    };

    router
}
