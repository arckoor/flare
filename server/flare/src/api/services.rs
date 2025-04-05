use std::sync::Arc;

use axum::{body::Body, response::IntoResponse};
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::store::Store;

use super::{api_params::FileName, error::RestError};

pub async fn serve_image(
    store: Arc<Store>,
    name: FileName,
    request: axum::http::Request<Body>,
) -> Result<impl IntoResponse, RestError> {
    let path = store.image_path.join(&name);
    if !path.exists() {
        // todo these can maybe be soft fails
        return Err(RestError::internal(""));
    }

    // TODO there is also new_with_mime
    let svc = ServeFile::new(path);
    Ok(svc.oneshot(request).await)
}
