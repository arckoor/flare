use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
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

use crate::prisma::Permissions;
use crate::store::Store;

use super::api_params::{LoginInfo, TokenResponse};
use super::error::RestError;

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
        .route(
            "/test-protected-route2",
            routing::get(test_protected_route2),
        )
        .with_state(state);

    // TODO for some reason the "try it out button" still works, it should be disabled
    let router = router.merge(
        SwaggerUi::new("/swagger-ui")
            .url("/api-docs/openapi.json", ApiDoc::openapi())
            .config(Config::default().try_it_out_enabled(false).filter(true)),
    );

    #[cfg(debug_assertions)]
    let router = Router::new().nest("/api", router);

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
        // TODO this sucks, for obvious reasons
        if user.password == login_info.password {
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
) -> Result<impl IntoResponse, RestError> {
    let redirect_uri = match query.get("redirect_uri") {
        Some(redirect_uri) => redirect_uri.clone(),
        None => "http://localhost:3000".to_string(),
    };
    let (url, _) = store.d_oauth.auth_url(redirect_uri).await?;
    Ok((StatusCode::FOUND, [(header::LOCATION, url.to_string())]))
}

async fn oauth_callback(
    State(store): State<Arc<Store>>,
    Query(query): Query<HashMap<String, String>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, RestError> {
    let code = query
        .get("code")
        .ok_or_else(|| RestError::bad_req("No code provided"))?;
    let state = query
        .get("state")
        .ok_or_else(|| RestError::bad_req("No state provided"))?;

    let (discord_id, discord_username, redirect_uri) =
        store.d_oauth.callback(code.clone(), state.clone()).await?;

    let user = store
        .db
        .get_or_create_discord_user(discord_id, discord_username)
        .await?;

    let (access, jar) = store.jwt.login(&user, jar).await?;

    Ok((
        StatusCode::FOUND,
        [(header::LOCATION, redirect_uri)],
        jar,
        Json(TokenResponse { access }),
    ))
}

async fn logout(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, RestError> {
    let claims = store.jwt.validate(auth, vec![]).await?;
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
    store
        .jwt
        .validate(auth, vec![Permissions::CreatePolls])
        .await?;

    Ok(Json(
        json!({ "message": "You are authorized to view this" }),
    ))
}

async fn test_protected_route2(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    store
        .jwt
        .validate(auth, vec![Permissions::DeletePolls])
        .await?;

    Ok(Json(
        json!({ "message": "You are authorized to view this" }),
    ))
}
