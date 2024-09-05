use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Multipart, Query, State};
use axum::response::IntoResponse;
use axum::{routing, Json, Router};
use axum_extra::extract::CookieJar;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use cookie::Cookie;
use hyper::{header, StatusCode};
use serde_json::json;
use utoipa::OpenApi;
use utoipa_swagger_ui::{Config, SwaggerUi};

use crate::crypto::verify_password;
use crate::prisma::{image, poll, user, Permissions};
use crate::requires;
use crate::store::Store;
use crate::util::calculate_aspect_ratio;

use super::api_params::{CreatePoll, LoginInfo, TokenResponse, UploadedImage};
use super::error::{FoundError, RestError};
use super::openapi::ApiDoc;

pub fn build_router(state: Arc<Store>) -> Router {
    let router = Router::new()
        .route("/signup", routing::post(signup))
        .route("/login", routing::post(login))
        .route("/oauth/discord/login", routing::get(oauth_login))
        .route("/oauth/discord/callback", routing::get(oauth_callback))
        .route("/logout", routing::get(logout))
        .route("/refresh", routing::get(refresh))
        .route("/test-protected-route", routing::get(test_protected_route))
        // authentication required
        .route("/image/upload", routing::post(add_image))
        .route("/image/{id}", routing::get(fetch_image))
        .route("/image/{id}", routing::delete(remove_image))
        .route("/poll", routing::post(create_poll))
        .route("/poll/{id}", routing::get(fetch_poll))
        .route("/poll/{id}", routing::patch(edit_poll))
        .route("/poll/{id}", routing::delete(remove_poll))
        .route("/poll/{id}/results", routing::get(organizer_results))
        // .route("/scheduled/{id}/submit", routing::post(add_scheduled_image))
        // user facing, i.e. public voting
        .route("/v/poll/{id}", routing::get(fetch_voting_poll))
        .route("/v/image/{id}", routing::get(fetch_voting_image))
        .route("/v/poll/{id}/vote", routing::post(vote))
        .route("/v/poll/{id}/results", routing::get(results))
        .with_state(state);

    let router = router.merge(
        SwaggerUi::new("/swagger-ui")
            .url("/api-docs/openapi.json", ApiDoc::openapi())
            .config(Config::new(["/api/api-docs/openapi.json"])),
    );

    let router = Router::new().nest("/api", router);

    // TODO we have an api documentation, but no CORS
    // let router = router.layer(
    //     CorsLayer::new()
    //         .allow_origin(vec!["https://localhost".parse::<HeaderValue>().unwrap()])
    //         .allow_headers([axum::http::header::CONTENT_TYPE])
    //         .allow_methods(["*".parse().unwrap()]), // .allow_credentials(true),
    // );

    router
}

#[cfg_attr(feature = "api-doc", utoipa::path(
    post,
    path = "/api/signup",
    request_body = LoginInfo,
    responses(
        (status = OK, description = "User created"),
        (status = INTERNAL_SERVER_ERROR, description = "Failed to create user or error executing query"),
    )
))]
async fn signup(
    State(state): State<Arc<Store>>,
    Json(login_info): Json<LoginInfo>,
) -> Result<impl IntoResponse, RestError> {
    let user = state.db.create_credentials_user(login_info).await?;

    // TODO why are we returning the user?
    Ok(Json(json!({ "message": "User created", "user": user })))
}

#[cfg_attr(feature = "api-doc", utoipa::path(
    post,
    path = "/api/login",
    request_body = LoginInfo,
    responses(
        (status = OK, body = TokenResponse, description = "User logged in"),
        (status = NOT_FOUND, description = "User not found"),
        (status = UNAUTHORIZED, description = "Invalid username or password"),
        (status = INTERNAL_SERVER_ERROR, description = "Failed to create token or error executing query"),
    )
))]
async fn login(
    State(store): State<Arc<Store>>,
    jar: CookieJar,
    Json(login_info): Json<LoginInfo>,
) -> Result<impl IntoResponse, RestError> {
    let user = store.db.get_credential_user(login_info.username).await?;
    if let Some(user) = user {
        if verify_password(user.password, &login_info.password).is_ok() {
            let (access, jar) = store
                .jwt
                .login(
                    &user
                        .user
                        .expect("Every credential user must be related to a user"),
                    jar,
                )
                .await?;

            return Ok((jar, Json(TokenResponse { access })));
        }
    }
    Err(RestError::unauthorized("Invalid username or password"))
}

async fn oauth_login(
    State(store): State<Arc<Store>>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, FoundError> {
    let redirect_uri = match query.get("redirect_uri") {
        Some(redirect_uri) => redirect_uri.clone(),
        None => "/".to_string(),
    };
    let url = store.d_oauth.auth_url(redirect_uri).await?;
    Ok((StatusCode::FOUND, [(header::LOCATION, url.to_string())]))
}

async fn oauth_callback(
    State(store): State<Arc<Store>>,
    Query(query): Query<HashMap<String, String>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, FoundError> {
    let code = query
        .get("code")
        .ok_or_else(|| FoundError::new(store.d_oauth.login_url(), "".to_string()))?;
    let state = query
        .get("state")
        .ok_or_else(|| FoundError::new(store.d_oauth.login_url(), "".to_string()))?;

    let (discord_id, discord_username, redirect_uri) =
        store.d_oauth.callback(code.clone(), state.clone()).await?;

    let user = store
        .db
        .get_or_create_discord_user(discord_id, discord_username)
        .await
        .map_err(|_| FoundError::new(store.d_oauth.login_url(), "".to_string()))?;

    let (_, jar) = store
        .jwt
        .login(&user, jar)
        .await
        .map_err(|_| FoundError::new(store.d_oauth.login_url(), "".to_string()))?;

    Ok((StatusCode::FOUND, [(header::LOCATION, redirect_uri)], jar))
}

async fn logout(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth);
    store.jwt.revoke(claims.sub).await?;
    let jar = jar.remove(Cookie::from("refresh_token"));

    Ok((jar, StatusCode::NO_CONTENT))
}

async fn refresh(
    State(store): State<Arc<Store>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, RestError> {
    let (access, jar) = store.jwt.refresh(jar).await?;
    Ok((jar, Json(TokenResponse { access })))
}

#[cfg_attr(feature = "api-doc", utoipa::path(
    post,
    path = "/api/test-protected-route",
    request_body = LoginInfo,
    responses(
        (status = OK, body = TokenResponse, description = "User logged in"),
        (status = NOT_FOUND, description = "User not found"),
        (status = UNAUTHORIZED, description = "Invalid username or password"),
        (status = INTERNAL_SERVER_ERROR, description = "Failed to create token or error executing query"),
    ),
    security(("bearer-auth" = []))
))]
async fn test_protected_route(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    requires!(store, auth, Permissions::CreatePolls);

    Ok(Json(
        json!({ "message": "You are authorized to view this" }),
    ))
}

pub async fn fetch_image(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    Ok(())
}

#[cfg_attr(feature = "api-doc", utoipa::path(
    post,
    path = "/api/upload",
    request_body(content = Vec<u8>, description = "Multipart file", content_type = "multipart/form-data"),
    responses(
        (status = OK, body = UploadedImage, description = "Image uploaded"),
        (status = BAD_REQUEST, description = "Invalid content type"),
        (status = INTERNAL_SERVER_ERROR, description = "Failed to create image or error executing query"),
    ),
    security(("bearer-auth" = []))
))]
async fn add_image(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth);

    if let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| RestError::bad_req("Failed to parse multipart"))?
    {
        let content_type: mime::Mime = field
            .content_type()
            .ok_or(RestError::bad_req("No content type"))?
            .parse()
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

        let aspect_ratio = calculate_aspect_ratio(&data, content_type)?;

        let filename = format!("{}.{}", cuid2::create_id(), extension);
        let path = store.image_path.join(&filename);

        let mut file = tokio::fs::File::create(&path)
            .await
            .map_err(|_| RestError::internal("Failed to create file"))?;

        tokio::io::copy(&mut &*data, &mut file)
            .await
            .map_err(|_| RestError::internal("Failed to write to file"))?;

        store
            .db
            .prisma
            .image()
            .create(
                false,
                filename.clone(),
                aspect_ratio,
                user::id::equals(claims.sub),
                false,
                vec![],
            )
            .exec()
            .await?;
        return Ok(Json(UploadedImage { name: filename }));
    }

    Err(RestError::bad_req("No file provided"))
}

pub async fn remove_image(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    Ok(())
}

pub async fn create_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(create_poll): Json<CreatePoll>,
) -> Result<(), RestError> {
    let claims = requires!(store, auth, Permissions::CreatePolls);
    let images = store
        .db
        .prisma
        .image()
        .find_many(vec![
            image::user::is(vec![user::id::equals(claims.sub)]),
            image::name::in_vec(create_poll.images.clone()),
            image::poll_id::equals(None),
        ])
        .exec()
        .await?;

    if images.len() != create_poll.images.len() {
        return Err(RestError::bad_req("Invalid images"));
    }

    let cuid2 = cuid2::CuidConstructor::new().with_length(8);
    let short_link = cuid2.create_id();

    store
        .db
        .prisma
        ._transaction()
        .run(|client| async move {
            let poll = client
                .poll()
                .create(
                    short_link,
                    create_poll.title.clone(),
                    create_poll.info.clone(),
                    create_poll.ends.into(),
                    user::id::equals(claims.sub),
                    false,
                    vec![],
                )
                .exec()
                .await?;
            for image in images {
                client
                    .image()
                    .update(
                        image::id::equals(image.id),
                        vec![image::poll::connect(poll::id::equals(poll.id))],
                    )
                    .exec()
                    .await?;
            }

            Ok::<_, RestError>(())
        })
        .await?;

    Ok(())
}

pub async fn fetch_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    Ok(())
}

pub async fn edit_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    Ok(())
}

pub async fn remove_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    Ok(())
}

pub async fn organizer_results(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    Ok(())
}

pub async fn fetch_voting_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    Ok(())
}

pub async fn fetch_voting_image(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    Ok(())
}

pub async fn vote(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    Ok(())
}

pub async fn results(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    Ok(())
}
