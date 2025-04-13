use std::{fmt::Display, path::Path, str::FromStr, sync::Arc};

use axum::{body::Body, response::IntoResponse};
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
        tracing::warn!("Image file {} not found", name);
        return Err(RestError::internal("Image not found"));
    }

    let mime = mime::Mime::from_str(&mime).map_err(|_| {
        tracing::warn!("Got invalid mime type {} from db for image {}", mime, name);
        RestError::bad_req(format!("Invalid content type: {}", mime))
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
