pub mod admin;
pub mod auth;
pub mod groups;
pub mod polls;
pub mod voting;

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Multipart, State},
    response::IntoResponse,
    routing,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use sea_orm::{Set, TransactionTrait, entity::prelude::*};
use utoipa::OpenApi;

use crate::{crypto::primitives::Hasher, store::Store};
use crate::{requires, transaction};

use super::api_params::{AddImage, FileName, UploadedImage};
use super::error::RestError;
use super::openapi::ApiDoc;
use super::services::{remove_file, serve_image};
use super::validation::inspect_validate_image;

pub fn build_router(state: Arc<Store>) -> Router {
    let router = Router::new()
        .route("/ping", routing::get(ping))
        .route("/auth-ping", routing::get(auth_ping))
        .route(
            "/image",
            routing::post(add_image).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
        .route("/image/{name}", routing::get(fetch_image))
        .route("/image/{name}", routing::delete(remove_image))
        .route(
            "/docs/openapi.json",
            routing::get(move || async { Json(ApiDoc::openapi()) }),
        )
        .merge(admin::build_router())
        .merge(auth::build_router())
        .merge(groups::build_router())
        .merge(polls::build_router())
        .merge(voting::build_router(state.clone()))
        .with_state(state)
        .merge(
            utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
                .config(utoipa_swagger_ui::Config::from("/api/docs/openapi.json")),
        );

    Router::new().nest("/api", router)
}

#[utoipa::path(
    get,
    description = "Ping the api",
    path = "/api/ping",
    tag = "health",
    responses(
        (status = OK, description = "Pong"),
    ),
)]
async fn ping() -> impl IntoResponse {
    "Pong"
}

#[utoipa::path(
    get,
    description = "Ping the api (requires authentication)",
    path = "/api/auth-ping",
    tag = "health",
    responses(
        (status = OK, description = "Pong"),
        (status = UNAUTHORIZED, description = "Unauthorized"),
    ),
    security(("ac-base" = [])),
)]
async fn auth_ping(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    requires!(store, auth)?;
    Ok("Pong")
}

#[utoipa::path(
    post,
    path = "/api/image",
    description = "Upload an image",
    tag = "images",
    request_body(content = inline(AddImage), description = "Multipart file", content_type = "multipart/form-data", encoding(("image" = (content_type = "image/png")))),
    responses(
        (status = OK, body = UploadedImage, description = "Image uploaded"),
        (status = BAD_REQUEST, description = "Invalid content type or no file provided"),
    ),
    security(("ac-base" = [])),
)]
async fn add_image(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| RestError::bad_req("Failed to parse multipart"))?
    else {
        return Err(RestError::bad_req("No file provided"));
    };

    let content_type = field
        .content_type()
        .ok_or_else(|| RestError::bad_req("No content type"))?
        .parse::<mime::Mime>()
        .map_err(|_| RestError::bad_req("Invalid content type"))?;
    if content_type != mime::IMAGE_PNG && content_type != mime::IMAGE_JPEG {
        return Err(RestError::bad_req("Invalid content type"));
    }

    let extension = if content_type == mime::IMAGE_PNG {
        "png"
    } else {
        "jpeg"
    };

    let data = field
        .bytes()
        .await
        .map_err(|_| RestError::bad_req("Failed to read field"))?;

    let aspect_ratio = inspect_validate_image(&data, &content_type)?;
    let hash = Hasher::hash(&data)?;

    let filename = format!("{}.{}", cuid2::create_id(), extension);
    let path = store.image_path.join(&filename);

    transaction!(&store.db.sea, txn, {
        let mut file = tokio::fs::File::create_new(&path).await?;

        tokio::io::copy(&mut &*data, &mut file).await?;

        sea_entity::image::ActiveModel {
            id: Set(filename.clone()),
            aspect_ratio: Set(aspect_ratio),
            mime: Set(content_type.to_string()),
            hash: Set(hash),
            owner_id: Set(Some(claims.sub.clone())),
            ..Default::default()
        }
        .insert(txn)
        .await?;

        Ok(Json(UploadedImage { name: filename }))
    })
}

#[utoipa::path(
    get,
    path = "/api/image/{name}",
    description = "Retrieve an image",
    tag = "images",
    params(
        ("name" = FileName, Path, description = "Name of the image")
    ),
    responses(
        (status = OK, body = [u8], content(("image/png"), ("image/jpeg")), description = "The requested image"),
        (status = BAD_REQUEST, description = "Invalid file name"),
        (status = NOT_FOUND, description = "Image not found"),
    ),
    security(("ac-base" = [])),
)]
async fn fetch_image(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(name): axum::extract::Path<FileName>,
    request: axum::http::Request<Body>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let image = sea_entity::image::Entity::find_by_id(&name.0)
        .one(&store.db.sea)
        .await?;

    let Some(image) = image else {
        return Err(RestError::not_found("Image not found"));
    };

    // todo if it is scheduled, it should be fetchable by those users too

    if !(image.owner_id.is_some_and(|id| id == claims.sub)
        || image.group_id.is_some_and(|id| claims.groups.contains(&id)))
    {
        return Err(RestError::not_found("Image not found"));
    }

    serve_image(store, name, image.mime, request).await
}

#[utoipa::path(
    delete,
    path = "/api/image/{name}",
    description = "Remove an image",
    tag = "images",
    params(
        ("name" = FileName, Path, description = "Name of the image")
    ),
    responses(
        (status = OK, description = "Image removed"),
        (status = BAD_REQUEST, description = "Invalid file name"),
        (status = FORBIDDEN, description = "Image is in use"),
        (status = NOT_FOUND, description = "Image not found"),
    ),
    security(("ac-base" = [])),
)]
async fn remove_image(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(name): axum::extract::Path<FileName>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let image = sea_entity::image::Entity::find_by_id(&name.0)
        .filter(sea_entity::image::Column::OwnerId.eq(&claims.sub))
        .find_also_related(sea_entity::poll::Entity)
        .one(&store.db.sea)
        .await?;

    let Some((_, poll)) = image else {
        return Err(RestError::not_found("Image not found"));
    };

    if poll.is_some() {
        return Err(RestError::forbidden("Image is in use"));
    }

    let image_id = name.0.clone();
    transaction!(&store.db.sea, txn, {
        let res = sea_entity::image::Entity::delete_by_id(&image_id)
            .filter(sea_entity::image::Column::PollId.is_null())
            .exec(txn)
            .await?;

        if res.rows_affected != 1 {
            return Err(RestError::conflict("Image was modified"));
        }

        Ok(())
    })?;

    let path = store.image_path.join(&name);
    remove_file(&path, &name).await;

    Ok(())
}
