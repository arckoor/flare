use std::{fmt::Display, path::Path, str::FromStr, sync::Arc};

use axum::{body::Body, extract::Request, response::IntoResponse};
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::store::Store;

use super::{api_params::FileName, error::RestError};

pub async fn serve_image(
    store: Arc<Store>,
    name: FileName,
    mime: String,
    request: axum::http::Request<Body>,
) -> Result<impl IntoResponse, RestError> {
    let path = store.image_path.join(&name);
    if !path.exists() {
        return Err(RestError::internal(format!("Image file {name} not found",)));
    }

    let mime = mime::Mime::from_str(&mime).map_err(|_| {
        RestError::internal(format!(
            "Got invalid mime type {mime} from db for image {name}",
        ))
    })?;

    let svc = ServeFile::new_with_mime(path, &mime);
    Ok(svc.oneshot(request).await)
}

pub async fn remove_file(path: &Path, name: impl Display) {
    if path.exists() {
        if tokio::fs::remove_file(path).await.is_err() {
            tracing::warn!("Failed to remove image file {}", name);
        }
    } else {
        tracing::warn!("Image file {} not found, but was present in db!", name);
    }
}

pub fn extract_ip(req: &Request) -> Option<String> {
    req.headers()
        .get("cf-connecting-ip")
        .or_else(|| req.headers().get("X-Forwarded-For"))
        .and_then(|header_value| {
            header_value
                .to_str()
                .ok()
                .and_then(|s| s.split(',').next().map(|s| s.trim().to_string()))
        })
        .or_else(|| {
            req.extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|connect_info| connect_info.0.ip().to_string())
        })
}
