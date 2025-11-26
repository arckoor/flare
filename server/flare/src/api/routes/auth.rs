use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State, rejection::QueryRejection},
    response::IntoResponse,
    routing,
};
use axum_extra::{
    TypedHeader,
    extract::CookieJar,
    headers::{Authorization, authorization::Bearer},
};
use hyper::{
    StatusCode,
    header::{self},
};
use sea_entity::sea_orm_active_enums::{OauthProvider, Permissions};
#[cfg(feature = "sim")]
use sea_orm::Iterable;
use sea_orm::{TransactionTrait, entity::prelude::*};

use crate::{
    api::{
        api_params::{OAuthCallback, OAuthLogin, TokenResponse, UserInfo},
        error::{FoundError, RestError},
        services::remove_file,
    },
    store::Store,
};
use crate::{requires, transaction};

#[cfg(feature = "sim")]
use crate::api::api_params::LoginInfo;

pub fn build_router() -> Router<Arc<Store>> {
    let router = Router::new()
        .route("/oauth/{provider}/login", routing::get(oauth_login))
        .route("/oauth/{provider}/callback", routing::get(oauth_callback))
        .route("/oauth/{provider}/unlink", routing::delete(oauth_unlink))
        .route("/user", routing::get(user_info))
        .route("/user", routing::delete(remove_user))
        .route("/logout", routing::post(logout))
        .route("/refresh", routing::post(refresh));

    #[cfg(feature = "sim")]
    let router = router.route("/login", routing::post(login));

    router
}

#[cfg(feature = "sim")]
async fn login(
    State(store): State<Arc<Store>>,
    jar: CookieJar,
    Json(login_info): Json<LoginInfo>,
) -> Result<impl IntoResponse, RestError> {
    // This is for testing purposes only

    if let Some(user) = sea_entity::user::Entity::find_by_id(&login_info.id)
        .one(&store.db.sea)
        .await?
    {
        use crate::api::api_params::TokenResponse;

        let (access, jar) = store.jwt.login(&user, jar).await?;
        return Ok((jar, Json(TokenResponse { access })));
    } else {
        use sea_orm::ActiveValue::Set;

        let user = sea_entity::user::ActiveModel {
            id: Set(login_info.id.clone()),
            permissions: Set(Permissions::iter()
                .filter(|&perm| perm != Permissions::Admin)
                .collect()),
            ..Default::default()
        }
        .insert(&store.db.sea)
        .await?;

        let (access, jar) = store.jwt.login(&user, jar).await?;
        return Ok((jar, Json(TokenResponse { access })));
    }
}

#[utoipa::path(
    get,
    path = "/api/oauth/{provider}/login",
    description = "Login with an OAuth provider. If authentication is provided, link the OAuth account to your user",
    tag = "oauth",
    params(
        ("provider" = OauthProvider, Path, description = "An OAuth provider"),
        OAuthLogin,
    ),
    responses(
        (status = FOUND, headers(("Location", description = "OAuth login url"))),
    ),
    security((), ("ac-base" = [])),
)]
async fn oauth_login(
    State(store): State<Arc<Store>>,
    axum::extract::Path(provider): axum::extract::Path<OauthProvider>,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    query: Result<Query<OAuthLogin>, QueryRejection>,
) -> Result<impl IntoResponse, FoundError> {
    let existing_user = if let Some(auth) = auth {
        let claims = requires!(store, auth.0)
            .map_err(|_| FoundError::new(store.oauth.login_url(), "".to_string()))?;
        Some(claims.sub.clone())
    } else {
        None
    };

    let redirect_uri = match query {
        // TODO we should think very carefully about this again so we don't run into an SSRF vuln
        Ok(query) => query
            .redirect_url
            .clone()
            .unwrap_or_else(|| "/".to_string()),
        Err(_) => return Err(FoundError::new(store.oauth.login_url(), "".to_string())),
    };

    let url = match provider {
        OauthProvider::Discord => store
            .oauth
            .discord
            .auth_url(redirect_uri, existing_user)
            .await?
            .to_string(),
        OauthProvider::Github => store
            .oauth
            .github
            .auth_url(redirect_uri, existing_user)
            .await?
            .to_string(),
    };

    Ok((StatusCode::FOUND, [(header::LOCATION, url.to_string())]))
}

#[utoipa::path(
    get,
    path = "/api/oauth/{provider}/callback",
    description = "Callback used by OAuth providers",
    tag = "oauth",
    params(
        ("provider" = OauthProvider, Path, description = "An OAuth provider"),
        OAuthCallback,
    ),
    responses(
        (status = FOUND, headers(("Location", description = "Redirect url"))),
    ),
)]
async fn oauth_callback(
    State(store): State<Arc<Store>>,
    axum::extract::Path(provider): axum::extract::Path<OauthProvider>,
    query: Result<Query<OAuthCallback>, QueryRejection>,
    jar: CookieJar,
) -> Result<impl IntoResponse, FoundError> {
    let (code, state) = match query {
        Ok(query) => (query.code.clone(), query.state.clone()),
        Err(_) => return Err(FoundError::new(store.oauth.login_url(), "".to_string())),
    };

    let (oauth_id, redirect_uri, existing_user) = match provider {
        OauthProvider::Discord => store.oauth.discord.callback(code, state).await?,
        OauthProvider::Github => store.oauth.github.callback(code, state).await?,
    };

    let user = store
        .db
        .get_or_create_or_link_oauth_user(oauth_id, provider, existing_user)
        .await
        .map_err(|_| FoundError::new(store.oauth.login_url(), "".to_string()))?;

    let (_, jar) = store
        .jwt
        .login(&user, jar)
        .await
        .map_err(|_| FoundError::new(store.oauth.login_url(), "".to_string()))?;

    Ok((StatusCode::FOUND, [(header::LOCATION, redirect_uri)], jar))
}

#[utoipa::path(
    delete,
    path = "/api/oauth/{provider}/unlink",
    description = "Remove an OAuth account from your user",
    tag = "oauth",
    params(
        ("provider" = OauthProvider, Path, description = "An OAuth provider"),
    ),
    responses(
        (status = OK, description = "Account unlinked"),
        (status = NOT_FOUND, description = "Account not found"),
        (status = FORBIDDEN, description = "Unlinking not allowed"),
    ),
    security(("ac-base" = [])),
)]
async fn oauth_unlink(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(provider): axum::extract::Path<OauthProvider>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let connections = sea_entity::o_auth_user::Entity::find()
        .filter(sea_entity::o_auth_user::Column::UserId.eq(&claims.sub))
        .all(&store.db.sea)
        .await?;

    if !connections.iter().any(|model| model.provider == provider) {
        return Err(RestError::not_found("Connected account not found"));
    }

    if connections.len() == 1 {
        return Err(RestError::forbidden("Cannot remove only connection"));
    }

    sea_entity::o_auth_user::Entity::delete_by_id((claims.sub.clone(), provider))
        .exec(&store.db.sea)
        .await?;

    store.jwt.revoke_access(&claims.sub).await?;

    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/user",
    description = "Retrieve info about yourself",
    tag = "auth",
    responses(
        (status = OK, body = UserInfo),
    ),
    security(("ac-base" = [])),
)]
async fn user_info(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let logins = sea_entity::o_auth_user::Entity::find()
        .filter(sea_entity::o_auth_user::Column::UserId.eq(&claims.sub))
        .all(&store.db.sea)
        .await?
        .into_iter()
        .map(|model| (model.provider, model.provider_user_id))
        .collect();

    Ok(Json(UserInfo { logins }))
}

#[utoipa::path(
    delete,
    path = "/api/user",
    description = "Delete your account",
    tag = "auth",
    responses(
        (status = OK, description = "Account removed"),
        (status = FORBIDDEN, description = "Account removal not allowed"),
    ),
    security(("ac-base" = [])),
)]
async fn remove_user(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    if claims.permissions.contains(&Permissions::Admin) {
        return Err(RestError::forbidden("You cannot delete your account"));
    }

    if sea_entity::group::Entity::find()
        .filter(sea_entity::group::Column::OwnerId.eq(&claims.sub))
        .count(&store.db.sea)
        .await?
        != 0
    {
        return Err(RestError::forbidden(
            "You have owned groups, transfer or delete them",
        ));
    }

    let polls = sea_entity::poll::Entity::find()
        .filter(sea_entity::poll::Column::OwnerId.eq(&claims.sub))
        .all(&store.db.sea)
        .await?;

    let user_id = claims.sub.clone();
    let images = transaction!(&store.db.sea, txn, {
        let images = sea_entity::image::Entity::delete_many()
            .filter(sea_entity::image::Column::OwnerId.eq(&user_id))
            .exec_with_returning(txn)
            .await?
            .into_iter()
            .map(|image| image.id)
            .collect::<Vec<_>>();

        for poll in polls {
            sea_entity::poll::Entity::delete_by_id(&poll.id)
                .exec(txn)
                .await?;
        }

        sea_entity::user::Entity::delete_by_id(&user_id)
            .exec(txn)
            .await?;

        Ok(images)
    })?;

    for image in images {
        let path = store.image_path.join(&image);
        remove_file(&path, &image).await;
    }

    let jar = store.jwt.revoke(&claims.sub, jar).await?;

    Ok((StatusCode::NO_CONTENT, jar))
}

#[utoipa::path(
    post,
    path = "/api/logout",
    description = "Logout from the service",
    tag = "auth",
    responses(
        (status = NO_CONTENT, description = "Logged out"),
    ),
    security(("ac-base" = []))
)]
async fn logout(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;
    let jar = store.jwt.revoke(&claims.sub, jar).await?;

    Ok((StatusCode::NO_CONTENT, jar))
}

#[utoipa::path(
    post,
    path = "/api/refresh",
    description = "Refresh your access and refresh tokens",
    tag = "auth",
    responses(
        (status = OK, body = TokenResponse, description = "Session refreshed"),
        (status = UNAUTHORIZED, description = "Invalid token"),
        (status = FORBIDDEN, description = "Token revoked"),
    ),
    security(("ac-refresh" = [])),
)]
async fn refresh(
    State(store): State<Arc<Store>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, RestError> {
    let (access, jar) = store.jwt.refresh(jar).await?;
    Ok((jar, Json(TokenResponse { access })))
}
