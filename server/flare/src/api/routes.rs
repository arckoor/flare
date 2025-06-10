use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Query, State, rejection::QueryRejection},
    middleware,
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
use rand::{rng, seq::SliceRandom};
use sea_entity::sea_orm_active_enums::{OauthProvider, Permissions};
use sea_orm::{IntoActiveModel, QueryOrder, Set, TransactionTrait, entity::prelude::*};
use sea_orm::{Iterable, JoinType, QuerySelect};
use utoipa::OpenApi;

use crate::{
    api::api_params::{IdString, UpdatedPoll},
    crypto::Hasher,
    db::Database,
    store::Store,
    time::now,
};
use crate::{requires, transaction, validate_text};

use super::api_params::{
    AddGroup, AddImage, AddPoll, EditGroup, EditPoll, FetchGroup, FetchPoll, FetchPollSort,
    FetchPolls, FetchResults, FetchVote, FetchVoteResults, FetchVotingPoll, FileName, Member,
    OAuthCallback, OAuthLogin, PaginatedPoll, Paginator, PublishResults, TokenResponse,
    UploadedImage, UserInfo, Vote,
};
use super::error::{FoundError, RestError};
use super::middleware::{InjectedEphemeralUser, set_tracking_cookie};
use super::openapi::ApiDoc;
use super::services::{remove_file, serve_image};
use super::validation::{inspect_validate_image, validate_paginator, validate_user_text};

#[cfg(feature = "sim")]
use super::api_params::LoginInfo;

pub fn build_router(state: Arc<Store>) -> Router {
    let router = Router::new()
        .route("/ping", routing::get(ping))
        .route("/auth-ping", routing::get(auth_ping))
        .route("/oauth/{provider}/login", routing::get(oauth_login))
        .route("/oauth/{provider}/callback", routing::get(oauth_callback))
        .route("/oauth/{provider}/unlink", routing::delete(oauth_unlink))
        .route("/user", routing::get(user_info))
        .route("/user", routing::delete(remove_user))
        .route("/logout", routing::post(logout))
        .route("/refresh", routing::post(refresh))
        .route(
            "/image",
            routing::post(add_image).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
        .route("/image/{name}", routing::get(fetch_image))
        .route("/image/{name}", routing::delete(remove_image))
        // we unfortunately need to duplicate the endpoint because otherwise you'd need to include the trailing slash in the url
        .route("/polls", routing::get(fetch_polls))
        .route("/polls/{group_id}", routing::get(fetch_polls))
        .route("/poll", routing::post(add_poll))
        .route("/poll/{id}", routing::get(fetch_poll))
        .route("/poll/{id}", routing::patch(edit_poll))
        .route("/poll/{id}", routing::delete(remove_poll))
        .route("/poll/{id}/{group_id}", routing::patch(add_poll_to_group))
        .route("/poll/{id}/results", routing::get(fetch_results))
        .route("/poll/{id}/results", routing::post(publish_results))
        .route("/group/{id}", routing::post(join_group))
        .route("/group/{id}", routing::delete(leave_group))
        .route("/groups", routing::post(add_group))
        .route("/groups/{id}", routing::get(fetch_group))
        .route("/groups/{id}", routing::patch(edit_group))
        .route("/groups/{id}", routing::delete(remove_group))
        .route("/groups/{id}/{user_id}", routing::post(add_group_user))
        .route("/groups/{id}/{user_id}", routing::delete(remove_group_user))
        .route(
            "/docs/openapi.json",
            routing::get(move || async { Json(ApiDoc::openapi()) }),
        );

    let voting_router = Router::new()
        .route("/image/{id}", routing::get(fetch_voting_image))
        .route("/poll/{id}", routing::get(fetch_voting_poll))
        .route("/poll/{id}/vote", routing::get(fetch_vote))
        .route("/poll/{id}/vote", routing::post(vote))
        .route("/poll/{id}/results", routing::get(fetch_voting_results))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            set_tracking_cookie,
        ));

    let router = router.nest("/v", voting_router);

    #[cfg(feature = "sim")]
    let router = router.route("/login", routing::post(login));

    let router = router.with_state(state).merge(
        utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
            .config(utoipa_swagger_ui::Config::from("/api/docs/openapi.json")),
    );

    Router::new().nest("/api", router)
}

#[utoipa::path(
    get,
    description = "Ping the api",
    path = "/api/ping",
    responses(
        (status = OK, description = "Pong"),
    ),
)]
async fn ping() -> impl IntoResponse {
    "Pong"
}

#[utoipa::path(
    get,
    description = "Ping the api",
    path = "/api/auth-ping",
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
        let (access, jar) = store.jwt.login(&user, jar).await?;
        return Ok((jar, Json(TokenResponse { access })));
    } else {
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
    let existing_user = match auth {
        Some(auth) => {
            let claims = requires!(store, auth.0)
                .map_err(|_| FoundError::new(store.oauth.login_url(), "".to_string()))?;
            Some(claims.sub.clone())
        }
        None => None,
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
        (status = FORBIDDEN, description = "Account removal not allowed")
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

#[utoipa::path(
    post,
    path = "/api/image",
    description = "Upload an image",
    tag = "images",
    request_body(content = inline(AddImage), description = "Multipart file", content_type = "multipart/form-data"),
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
        .ok_or(RestError::bad_req("No content type"))?
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
        (status = OK, body = [u8], description = "The requested image"),
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

// utoipa makes (Option<T>, Path) parameters required, so we're stuck with this
#[utoipa::path(
    get,
    path = "/api/polls",
    description = "Fetch a number of polls",
    tag = "polls",
    params(
        ("page" = Option<u64>, Query, minimum = 0),
        ("page_size"  = Option<u64>, Query, minimum = 0),
        ("asc" = Option<bool>, Query),
        ("sort_by" = Option<FetchPollSort>, Query)
    ),
    responses(
        (status = OK, body = FetchPolls, description = "The requested polls"),
        (status = BAD_REQUEST, description = "Bag paginator options provided"),
    ),
    security(("ac-base" = [])),
)]
async fn _fetch_polls() {}

#[utoipa::path(
    get,
    path = "/api/polls/{group_id}",
    description = "Fetch a number of polls",
    tag = "polls",
    params(
        ("group_id" = String, Path, description = "Group id to filter by"),
        ("page" = Option<u64>, Query, minimum = 0),
        ("page_size"  = Option<u64>, Query, minimum = 0),
        ("asc" = Option<bool>, Query),
        ("sort_by" = Option<FetchPollSort>, Query)
    ),
    responses(
        (status = OK, body = FetchPolls, description = "The requested polls"),
        (status = BAD_REQUEST, description = "Bag paginator options provided"),
    ),
    security(("ac-base" = [])),
)]
async fn fetch_polls(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Query(paginator): Query<Paginator<FetchPollSort>>,
    group_id: Option<axum::extract::Path<String>>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    // TODO would be cool to be able to filter by no-groups, e.g. "private" polls too

    validate_paginator(&paginator, 50)?;

    let pager = {
        let query = sea_entity::poll::Entity::find()
            .filter(Database::filter_polls(
                &claims.sub,
                claims.groups.clone(),
                group_id.map(|group_id| group_id.0),
            ))
            .order_by(
                match paginator.sort_by {
                    None | Some(FetchPollSort::CreatedAt) => sea_entity::poll::Column::CreatedAt,
                    Some(FetchPollSort::Title) => sea_entity::poll::Column::Title,
                    Some(FetchPollSort::Ends) => sea_entity::poll::Column::Ends,
                },
                if paginator.asc {
                    sea_orm::Order::Asc
                } else {
                    sea_orm::Order::Desc
                },
            );

        query.paginate(&store.db.sea, paginator.page_size)
    };

    let mut polls = Vec::new();

    for poll in pager.fetch_page(paginator.page).await? {
        let images = sea_entity::image::Entity::find()
            .filter(sea_entity::image::Column::PollId.eq(&poll.id))
            .find_with_related(sea_entity::vote::Entity)
            .all(&store.db.sea)
            .await?;

        let votes = images
            .into_iter()
            .fold(0, |acc, (_, votes)| acc + votes.len()) as u64;

        polls.push(PaginatedPoll {
            id: poll.id,
            title: poll.title,
            ends: poll.ends,
            votes,
        });
    }

    Ok(Json(FetchPolls {
        polls,
        page: paginator.page,
        page_count: pager.num_pages().await?,
    }))
}

#[utoipa::path(
    post,
    path = "/api/poll",
    description = "Add a poll",
    tag = "polls",
    request_body(content = AddPoll),
    responses(
        (status = OK, body = FetchPoll, description = "Poll created"),
        (status = BAD_REQUEST, description = "Bad options provided"),
    ),
    security(("ac-manage-polls" = [])),
)]
async fn add_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(add_poll): Json<AddPoll>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    validate_text!(&add_poll.title, &add_poll.info);

    if add_poll.images.len() < 2 {
        return Err(RestError::bad_req("Not enough images provided"));
    }

    match add_poll.allowed_votes {
        0 => return Err(RestError::bad_req("Allowed votes must be greater than 0")),
        amount if amount > add_poll.images.len() as u32 => {
            return Err(RestError::bad_req("Allowed votes exceeds image count"));
        }
        _ => {}
    }

    if let Some(group) = &add_poll.group {
        if !claims.groups.contains(group) {
            return Err(RestError::not_found("Group not found"));
        }
    }

    // TODO ends should probably be positive, also for edit_poll

    let short_link = cuid2::slug();

    transaction!(&store.db.sea, txn, {
        let poll = sea_entity::poll::ActiveModel {
            id: Set(short_link.clone()),
            title: Set(add_poll.title.clone()),
            info: Set(add_poll.info.clone()),
            ends: Set(add_poll.ends),
            allowed_votes: Set(add_poll
                .allowed_votes
                .try_into()
                .map_err(|_| RestError::bad_req("Invalid allowed votes"))?),
            owner_id: Set(if add_poll.group.is_some() {
                None
            } else {
                Some(claims.sub.clone())
            }),
            group_id: Set(add_poll.group.clone()),
            ..Default::default()
        }
        .insert(txn)
        .await?;

        // todo if the poll belongs to a group, the images need to too!
        let images = {
            let mut stmt = sea_entity::image::Entity::update_many().col_expr(
                sea_entity::image::Column::PollId,
                Expr::value(poll.id.clone()),
            );
            if let Some(group_id) = add_poll.group {
                // todo this sucks make extra call in Database:: or smth
                stmt = stmt
                    .col_expr(
                        sea_entity::image::Column::OwnerId,
                        Expr::value(None::<String>),
                    )
                    .col_expr(
                        sea_entity::image::Column::GroupId,
                        Expr::value(Some(group_id.clone())),
                    );
            }

            stmt
        }
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::image::Column::Id.is_in(add_poll.images.clone()))
                .add(sea_entity::image::Column::OwnerId.eq(claims.sub.clone()))
                .add(sea_entity::image::Column::PollId.is_null()),
        )
        .exec_with_returning(txn)
        .await?;

        if images.len() != add_poll.images.len() {
            return Err(RestError::bad_req("Invalid images"));
        }

        let aspect_ratios = images
            .iter()
            .map(|image| (image.id.clone(), image.aspect_ratio.clone()))
            .collect();

        Ok(Json(FetchPoll {
            id: poll.id,
            title: poll.title,
            info: poll.info,
            ends: poll.ends,
            allowed_votes: poll.allowed_votes as u32,
            votes: 0,
            images: images.into_iter().map(|image| image.id).collect(),
            aspect_ratios,
            group: poll.group_id,
            updated_at: poll.updated_at,
        }))
    })
}

#[utoipa::path(
    get,
    path = "/api/poll/{id}",
    description = "Fetch a poll",
    tag = "polls",
    params(
        ("id" = IdString, Path, description = "The poll id")
    ),
    responses(
        (status = OK, body = FetchPoll, description = "The requested poll"),
        (status = NOT_FOUND, description = "Poll not found"),
    ),
    security(("ac-base" = [])),
)]
async fn fetch_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .filter(Database::filter_polls(
            &claims.sub,
            claims.groups.clone(),
            None,
        ))
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let images = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::PollId.eq(&poll.id))
        .find_with_related(sea_entity::vote::Entity)
        .all(&store.db.sea)
        .await?;

    let votes = images.iter().fold(0, |acc, (_, votes)| acc + votes.len()) as u64;

    let images = images
        .into_iter()
        .map(|(image, _)| image)
        .collect::<Vec<_>>();

    let aspect_ratios = images
        .iter()
        .map(|image| (image.id.clone(), image.aspect_ratio.clone()))
        .collect();

    Ok(Json(FetchPoll {
        id: poll.id,
        title: poll.title,
        info: poll.info,
        ends: poll.ends,
        allowed_votes: poll.allowed_votes as u32,
        images: images.into_iter().map(|image| image.id).collect(),
        aspect_ratios,
        votes,
        group: poll.group_id,
        updated_at: poll.updated_at,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/poll/{id}",
    description = "Edit a poll",
    tag = "polls",
    params(
        ("id" = IdString, Path, description = "The poll id")
    ),
    request_body(content = EditPoll, description = "The fields to change"),
    responses(
        (status = OK, body = FetchPoll, description = "The updated poll"),
        (status = BAD_REQUEST, description = "Bad options provided"),
        (status = NOT_FOUND, description = "Poll not found"),
    ),
    security(("ac-manage-polls" = [])),
)]
async fn edit_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
    Json(edit_poll): Json<EditPoll>,
) -> Result<impl IntoResponse, RestError> {
    // TODO this function is too long.
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .filter(Database::filter_polls(
            &claims.sub,
            claims.groups.clone(),
            None,
        ))
        .find_with_related(sea_entity::image::Entity)
        .all(&store.db.sea)
        .await?;

    let Some((poll, current_images)) = poll.into_iter().next() else {
        return Err(RestError::not_found("Poll not found"));
    };

    if poll.locked {
        return Err(RestError::forbidden("Poll is locked"));
    }

    let new_image_count = (current_images.len() as u64)
        .saturating_add(edit_poll.add_images.as_ref().map_or(0, |x| x.len() as u64))
        .saturating_sub(
            edit_poll
                .remove_images
                .as_ref()
                .map_or(0, |x| x.len() as u64),
        );

    if new_image_count < 2 {
        return Err(RestError::bad_req("Not enough images provided"));
    }

    let allowed_votes = edit_poll.allowed_votes.unwrap_or(poll.allowed_votes as u32);

    if allowed_votes as u64 > new_image_count {
        return Err(RestError::bad_req("Allowed votes exceed image count"));
    }

    let remove_images = edit_poll.remove_images.clone();
    let poll_id = poll.id.clone();
    let group_id = poll.group_id.clone();

    let poll = transaction!(&store.db.sea, txn, {
        let mut poll = poll.into_active_model();

        poll.title.reset();

        if let Some(title) = edit_poll.title {
            validate_text!(&title);
            poll.title = Set(title);
        }

        if let Some(info) = edit_poll.info {
            validate_text!(&info);
            poll.info = Set(info);
        }

        if let Some(ends) = edit_poll.ends {
            poll.ends = Set(ends);
        }

        if let Some(allowed_votes) = edit_poll.allowed_votes {
            poll.allowed_votes = Set(allowed_votes as i32);
        }

        if let Some(add_images) = edit_poll.add_images {
            let res = {
                let mut stmt = sea_entity::image::Entity::update_many()
                    .col_expr(sea_entity::image::Column::PollId, Expr::value(id.0.clone()));

                if let Some(group_id) = group_id {
                    stmt = stmt
                        .col_expr(
                            sea_entity::image::Column::OwnerId,
                            Expr::value(None::<String>),
                        )
                        .col_expr(
                            sea_entity::image::Column::GroupId,
                            Expr::value(Some(group_id.clone())),
                        );
                }

                stmt
            }
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::image::Column::Id.is_in(add_images.clone()))
                    .add(sea_entity::image::Column::OwnerId.eq(claims.sub.clone()))
                    .add(sea_entity::image::Column::PollId.is_null()),
            )
            .exec(txn)
            .await?;

            if res.rows_affected != add_images.len() as u64 {
                return Err(RestError::bad_req("Invalid add images"));
            }
        }

        if let Some(remove_images) = &remove_images {
            let res = sea_entity::image::Entity::delete_many()
                .filter(
                    sea_orm::Condition::all()
                        .add(sea_entity::image::Column::Id.is_in(remove_images.clone()))
                        .add(sea_entity::image::Column::PollId.eq(id.0.clone())),
                )
                .exec(txn)
                .await?;

            if res.rows_affected != remove_images.len() as u64 {
                return Err(RestError::bad_req("Invalid remove images"));
            }
        }

        // Todo is this check really necessary?
        let images = sea_entity::image::Entity::find()
            .filter(sea_entity::image::Column::PollId.eq(&id.0))
            .all(txn)
            .await?;

        if images.len() as u64 != new_image_count {
            return Err(RestError::bad_req("Invalid image count"));
        }

        let polls = sea_entity::poll::Entity::update_many()
            .set(poll)
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::poll::Column::Id.eq(poll_id))
                    .add(sea_entity::poll::Column::UpdatedAt.eq(edit_poll.updated_at)),
            )
            .exec_with_returning(txn)
            .await?;

        if polls.len() != 1 {
            return Err(RestError::conflict("Poll was modified"));
        }

        let poll = polls.into_iter().next().unwrap();

        Ok(poll)
    })?;

    if let Some(remove_images) = edit_poll.remove_images {
        for image in remove_images {
            let path = store.image_path.join(&image);
            remove_file(&path, &image).await;
        }
    }

    let images = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::PollId.eq(&poll.id))
        .find_with_related(sea_entity::vote::Entity)
        .all(&store.db.sea)
        .await?;

    let votes = images.iter().fold(0, |acc, (_, votes)| acc + votes.len()) as u64;

    let images = images
        .into_iter()
        .map(|(image, _)| image)
        .collect::<Vec<_>>();

    let aspect_ratios = images
        .iter()
        .map(|image| (image.id.clone(), image.aspect_ratio.clone()))
        .collect();

    Ok(Json(FetchPoll {
        id: poll.id,
        title: poll.title,
        info: poll.info,
        ends: poll.ends,
        allowed_votes: poll.allowed_votes as u32,
        votes,
        images: images.into_iter().map(|image| image.id).collect(),
        aspect_ratios,
        group: poll.group_id,
        updated_at: poll.updated_at,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/poll/{id}",
    description = "Remove a poll",
    tag = "polls",
    params(
        ("id" = IdString, Path, description = "The poll id")
    ),
    responses(
        (status = OK, description = "Poll deleted"),
        (status = NOT_FOUND, description = "Poll not found"),
    ),
    security(("ac-manage-polls" = [])),
)]
async fn remove_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .filter(Database::filter_polls(
            &claims.sub,
            claims.groups.clone(),
            None,
        ))
        .one(&store.db.sea)
        .await?;

    if poll.is_none() {
        return Err(RestError::not_found("Poll not found"));
    }

    let poll_images = transaction!(&store.db.sea, txn, {
        let poll_images = sea_entity::image::Entity::delete_many()
            .filter(sea_entity::image::Column::PollId.eq(&id.0))
            .exec_with_returning(txn)
            .await?
            .into_iter()
            .map(|image| image.id)
            .collect::<Vec<_>>();

        sea_entity::poll::Entity::delete_by_id(&id.0)
            .exec(txn)
            .await?;

        Ok(poll_images)
    })?;

    for image in poll_images {
        let path = store.image_path.join(&image);
        remove_file(&path, &image).await;
    }

    Ok(())
}

#[utoipa::path(
    patch,
    path = "/api/poll/{id}/{group_id}",
    description = "Add a poll to a group",
    tag = "polls",
    params(
        ("id" = IdString, Path, description = "The poll id"),
        ("group_id" = IdString, Path, description = "The group id"),
    ),
    responses(
        (status = OK, body = UpdatedPoll, description = "Updated poll"),
        (status = NOT_FOUND, description = "Poll not found"),
    ),
    security(("ac-manage-polls" = [])),
)]
async fn add_poll_to_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path((id, group_id)): axum::extract::Path<(IdString, IdString)>,
    Json(updated_poll): Json<UpdatedPoll>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .filter(Database::filter_polls(&claims.sub, vec![], None))
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let group_user =
        sea_entity::group_user::Entity::find_by_id((group_id.0.clone(), claims.sub.clone()))
            .one(&store.db.sea)
            .await?;

    if group_user.is_none() {
        return Err(RestError::not_found("Group not found"));
    };

    transaction!(&store.db.sea, txn, {
        sea_entity::image::Entity::update_many()
            .col_expr(
                sea_entity::image::Column::OwnerId,
                Expr::value(None::<String>),
            )
            .col_expr(
                sea_entity::image::Column::GroupId,
                Expr::value(Some(group_id.0.clone())),
            )
            .filter(sea_entity::image::Column::PollId.eq(&id.0))
            .exec(txn)
            .await?;

        let mut poll = poll.into_active_model();
        poll.owner_id = Set(None);
        poll.group_id = Set(Some(group_id.0));

        let polls = sea_entity::poll::Entity::update_many()
            .set(poll)
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::poll::Column::Id.eq(id.0))
                    .add(sea_entity::poll::Column::UpdatedAt.eq(updated_poll.updated_at)),
            )
            .exec_with_returning(txn)
            .await?;

        // todo if the poll belongs to a group, the images need to too!

        if polls.len() != 1 {
            return Err(RestError::conflict("Poll was modified"));
        }

        let poll = polls.into_iter().next().unwrap();

        Ok(Json(UpdatedPoll {
            updated_at: poll.updated_at,
        }))
    })
}

#[utoipa::path(
    get,
    path = "/api/poll/{id}/results",
    description = "Fetch results for a poll",
    tag = "polls",
    params(
        ("id" = IdString, Path, description = "The poll id"),
    ),
    responses(
        (status = OK, body = FetchResults, description = "Poll results"),
        (status = NOT_FOUND, description = "Poll not found"),
    ),
    security(("ac-base" = [])),
)]
async fn fetch_results(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    // TODO this can be much more extensive, e.g. histograms, ...

    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .filter(Database::filter_polls(
            &claims.sub,
            claims.groups.clone(),
            None,
        ))
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let now = now().as_secs_f64();

    let images = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::PollId.eq(&poll.id))
        .find_with_related(sea_entity::vote::Entity)
        .all(&store.db.sea)
        .await?;

    let mut results = images
        .iter()
        .map(|(image, _)| (image.id.clone(), 0))
        .collect::<HashMap<_, u64>>();

    for vote in images.into_iter().flat_map(|(_, vote)| vote) {
        results.entry(vote.image_id).and_modify(|v| *v += 1);
    }

    Ok(Json(FetchResults {
        id: poll.id,
        votes: results,
        public: poll.results_public,
        ended: poll.ends < now,
        updated_at: poll.updated_at,
    }))
}

#[utoipa::path(
    post,
    path = "/api/poll/{id}/results",
    description = "(Un-)Publish the results for a poll",
    tag = "polls",
    params(
        ("id" = IdString, Path, description = "The poll id"),
    ),
    request_body(content = PublishResults),
    responses(
        (status = OK, body = UpdatedPoll, description = "Updated poll"),
        (status = NOT_FOUND, description = "Poll not found"),
    ),
    security(("ac-manage-polls" = [])),
)]
async fn publish_results(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
    Json(publish_results): Json<PublishResults>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .filter(Database::filter_polls(
            &claims.sub,
            claims.groups.clone(),
            None,
        ))
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let now = now().as_secs_f64();

    if poll.ends > now {
        return Err(RestError::bad_req("Poll is still active"));
    }

    if poll.results_public == publish_results.published {
        return Err(RestError::bad_req(
            "Results are already published / unpublished",
        ));
    }

    let mut poll = poll.into_active_model();
    poll.results_public = Set(publish_results.published);

    let polls = sea_entity::poll::Entity::update_many()
        .set(poll)
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::poll::Column::Id.eq(&id.0))
                .add(sea_entity::poll::Column::UpdatedAt.eq(publish_results.updated_at)),
        )
        .exec_with_returning(&store.db.sea)
        .await?;

    if polls.len() != 1 {
        return Err(RestError::conflict("Poll was modified"));
    }

    let poll = polls.into_iter().next().unwrap();

    Ok(Json(UpdatedPoll {
        updated_at: poll.updated_at,
    }))
}

#[utoipa::path(
    post,
    path = "/api/group/{id}",
    description = "Accept a group invite",
    tag = "groups",
    params(
        ("id" = IdString, Path, description = "The group id"),
    ),
    responses(
        (status = OK, description = "Group joined"),
        (status = NOT_FOUND, description = "Invite not found"),
    ),
    security(("ac-base" = [])),
)]
async fn join_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    tracing::warn!("huh? {id}");

    // TODO this currently assumes the invite link is shared out-of-band
    // available invites could also be shown to the user directly, but should include enough information
    // to uniquely identify the group the user would be joining

    if sea_entity::group_join_request::Entity::find_by_id((id.0.clone(), claims.sub.clone()))
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("Invite not found"));
    }

    let user_id = claims.sub.clone();
    transaction!(&store.db.sea, txn, {
        sea_entity::group_user::ActiveModel {
            group_id: Set(id.0.clone()),
            user_id: Set(user_id.clone()),
            ..Default::default()
        }
        .insert(txn)
        .await?;

        sea_entity::group_join_request::Entity::delete_by_id((id.0.clone(), user_id.clone()))
            .exec(txn)
            .await?;
        Ok(())
    })?;

    store.jwt.revoke_access(&claims.sub).await?;

    Ok(())
}

#[utoipa::path(
    delete,
    path = "/api/group/{id}",
    description = "Leave a group",
    tag = "groups",
    params(
        ("id" = IdString, Path, description = "The group id"),
    ),
    responses(
        (status = OK, description = "Group left"),
        (status = NOT_FOUND, description = "Group not found"),
    ),
    security(("ac-base" = [])),
)]
async fn leave_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let group_user = sea_entity::group_user::Entity::find_by_id((id.0.clone(), claims.sub.clone()))
        .one(&store.db.sea)
        .await?;

    if group_user.is_none() {
        return Err(RestError::not_found("Group not found"));
    };

    let user_id = claims.sub.clone();
    transaction!(&store.db.sea, txn, {
        Database::remove_user_from_group(txn, &id.0, &user_id).await
    })?;

    store.jwt.revoke_access(&claims.sub).await?;

    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/groups",
    description = "Add a group",
    tag = "groups",
    request_body(content = AddGroup),
    responses(
        (status = OK, body = FetchGroup, description = "Group created"),
        (status = BAD_REQUEST, description = "Bad options provided"),
    ),
    security(("ac-manage-groups" = [])),
)]
async fn add_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(add_group): Json<AddGroup>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManageGroups)?;

    validate_text!(&add_group.name);

    let owner_id = claims.sub.clone();
    let group = transaction!(&store.db.sea, txn, {
        let group = sea_entity::group::ActiveModel {
            id: Set(cuid2::create_id()),
            name: Set(add_group.name.clone()),
            owner_id: Set(owner_id.clone()),
            ..Default::default()
        }
        .insert(txn)
        .await?;

        sea_entity::group_user::ActiveModel {
            group_id: Set(group.id.clone()),
            user_id: Set(owner_id.clone()),
            ..Default::default()
        }
        .insert(txn)
        .await?;

        Ok(group)
    })?;

    store.jwt.revoke_access(&claims.sub).await?;

    Ok(Json(FetchGroup {
        id: group.id,
        name: group.name,
        owner: claims.sub.clone(),
        members: vec![Member { id: claims.sub }],
        updated_at: group.updated_at,
    }))
}

#[utoipa::path(
    get,
    path = "/api/groups/{id}",
    description = "Fetch info about a group",
    tag = "groups",
    params(
        ("id" = IdString, Path, description = "Group id")
    ),
    responses(
        (status = OK, body = FetchGroup, description = "The requested group"),
        (status = NOT_FOUND, description = "Group not found"),
    ),
    security(("ac-base" = [])),
)]
async fn fetch_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let group = sea_entity::group::Entity::find_by_id(&id.0)
        .filter(sea_entity::group::Column::Id.is_in(claims.groups.clone()))
        .find_with_related(sea_entity::group_user::Entity)
        .all(&store.db.sea)
        .await?;

    let Some((group, group_users)) = group.into_iter().next() else {
        return Err(RestError::not_found("Group not found"));
    };

    Ok(Json(FetchGroup {
        id: group.id,
        name: group.name,
        owner: group.owner_id,
        members: group_users
            .into_iter()
            .map(|group_user| Member {
                id: group_user.user_id,
            })
            .collect(),
        updated_at: group.updated_at,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/groups/{id}",
    description = "Edit a group",
    tag = "groups",
    params(
        ("id" = IdString, Path, description = "Group id")
    ),
    request_body(content = EditGroup, description = "The fields to change"),
    responses(
        (status = OK, body = FetchGroup, description = "The updated group"),
        (status = BAD_REQUEST, description = "Bad options provided"),
        (status = NOT_FOUND, description = "Group not found"),
    ),
    security(("ac-manage-groups" = [])),
)]
async fn edit_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
    Json(edit_group): Json<EditGroup>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManageGroups)?;

    let group = sea_entity::group::Entity::find_by_id(&id.0)
        .filter(sea_entity::group::Column::OwnerId.eq(&claims.sub))
        .one(&store.db.sea)
        .await?;

    let Some(group) = group else {
        return Err(RestError::not_found("Group not found"));
    };

    transaction!(store.db.sea, txn, {
        let mut group = group.into_active_model();
        group.name.reset();

        if let Some(name) = edit_group.name {
            validate_text!(&name);
            group.name = Set(name);
        }

        if let Some(owner_id) = edit_group.owner {
            if owner_id != claims.sub {
                let group_user =
                    sea_entity::group_user::Entity::find_by_id((id.0.clone(), owner_id.clone()))
                        .find_also_related(sea_entity::user::Entity)
                        .one(txn)
                        .await?;

                let Some((_, Some(new_owner))) = group_user else {
                    return Err(RestError::not_found("User not found"));
                };

                if !new_owner.permissions.contains(&Permissions::ManageGroups) {
                    return Err(RestError::forbidden("User cannot manage groups"));
                }

                group.owner_id = Set(owner_id);
            }
        }

        let groups = sea_entity::group::Entity::update_many()
            .set(group)
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::group::Column::Id.eq(&id.0))
                    .add(sea_entity::group::Column::UpdatedAt.eq(edit_group.updated_at)),
            )
            .exec_with_returning(txn)
            .await?;

        if groups.len() != 1 {
            return Err(RestError::conflict("Group was modified"));
        }

        let group = groups.into_iter().next().unwrap();
        let group_users = sea_entity::group_user::Entity::find()
            .filter(sea_entity::group_user::Column::GroupId.eq(&group.id))
            .all(txn)
            .await?;

        Ok(Json(FetchGroup {
            id: id.0,
            name: group.name,
            owner: group.owner_id,
            members: group_users
                .into_iter()
                .map(|group_user| Member {
                    id: group_user.user_id,
                })
                .collect(),
            updated_at: group.updated_at,
        }))
    })
}

#[utoipa::path(
    delete,
    path = "/api/groups/{id}",
    description = "Remove a group",
    tag = "groups",
    params(
        ("id" = IdString, Path, description = "Group id")
    ),
    responses(
        (status = OK, description = "Group removed"),
        (status = NOT_FOUND, description = "Group not found"),
    ),
    security(("ac-manage-groups" = [])),
)]
async fn remove_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManageGroups)?;

    let group = sea_entity::group::Entity::find_by_id(&id.0)
        .filter(
            sea_orm::query::Condition::all()
                .add(sea_entity::group::Column::OwnerId.eq(&claims.sub))
                .add(sea_entity::group_user::Column::GroupId.eq(&id.0)),
        )
        .find_with_related(sea_entity::group_user::Entity)
        .all(&store.db.sea)
        .await?;

    let Some((_, group_users)) = group.into_iter().next() else {
        return Err(RestError::not_found("Group not found"));
    };

    let poll_images = transaction!(&store.db.sea, txn, {
        let mut poll_images = Vec::new();
        for poll in sea_entity::poll::Entity::find()
            .filter(sea_entity::poll::Column::GroupId.eq(&id.0))
            .all(txn)
            .await?
        {
            poll_images.extend_from_slice(
                &sea_entity::image::Entity::delete_many()
                    .filter(sea_entity::image::Column::PollId.eq(&poll.id))
                    .exec_with_returning(txn)
                    .await?
                    .into_iter()
                    .map(|image| image.id)
                    .collect::<Vec<_>>(),
            );
        }

        sea_entity::poll::Entity::delete_many()
            .filter(sea_entity::poll::Column::GroupId.eq(&id.0))
            .exec(txn)
            .await?;

        sea_entity::group::Entity::delete_by_id(&id.0)
            .exec(txn)
            .await?;

        Ok(poll_images)
    })?;

    for image in poll_images {
        let path = store.image_path.join(&image);
        remove_file(&path, &image).await;
    }

    for user in group_users {
        store.jwt.revoke_access(&user.user_id).await?;
    }

    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/groups/{id}/{user_id}",
    description = "Invite a user to a group",
    tag = "groups",
    params(
        ("id" = IdString, Path, description = "Group id"),
        ("user_id" = IdString, Path, description = "User id to invite")
    ),
    responses(
        (status = OK, description = "User invited"),
        (status = BAD_REQUEST, description = "User already in group"),
        (status = NOT_FOUND, description = "Group or user not found"),
        (status = CONFLICT, description = "User already invited"),
    ),
    security(("ac-manage-groups" = [])),
)]
async fn add_group_user(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path((id, user_id)): axum::extract::Path<(IdString, IdString)>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManageGroups)?;

    if sea_entity::group::Entity::find_by_id(&id.0)
        .filter(sea_entity::group::Column::OwnerId.eq(&claims.sub))
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("Group not found"));
    }

    if sea_entity::user::Entity::find_by_id(&user_id.0)
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("User not found"));
    }

    if sea_entity::group_user::Entity::find_by_id((id.0.clone(), user_id.0.clone()))
        .one(&store.db.sea)
        .await?
        .is_some()
    {
        return Err(RestError::bad_req("User already in group"));
    }

    sea_entity::group_join_request::ActiveModel {
        group_id: Set(id.0),
        user_id: Set(user_id.0),
        ..Default::default()
    }
    .insert(&store.db.sea)
    .await?;

    Ok(())
}

#[utoipa::path(
    delete,
    path = "/api/groups/{id}/{user_id}",
    description = "Remove a user from a group",
    tag = "groups",
    params(
        ("id" = IdString, Path, description = "Group id"),
        ("user_id" = IdString, Path, description = "User id to remove")
    ),
    responses(
        (status = OK, description = "User removed"),
        (status = BAD_REQUEST, description = "Removing yourself is not allowed"),
        (status = NOT_FOUND, description = "Group not found or user not in group"),
    ),
    security(("ac-manage-groups" = [])),
)]
async fn remove_group_user(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path((id, user_id)): axum::extract::Path<(IdString, IdString)>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManageGroups)?;

    if claims.sub == user_id.0 {
        return Err(RestError::bad_req(
            "You cannot remove yourself from the group",
        ));
    }

    if sea_entity::group::Entity::find_by_id(&id.0)
        .filter(sea_entity::group::Column::OwnerId.eq(&claims.sub))
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("Group not found"));
    }

    if sea_entity::group_user::Entity::find_by_id((id.0.clone(), user_id.0.clone()))
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("User not in group"));
    }

    let inner_user_id = user_id.0.clone();
    transaction!(&store.db.sea, txn, {
        Database::remove_user_from_group(txn, &id.0, &inner_user_id).await
    })?;

    store.jwt.revoke_access(&user_id.0).await?;

    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v/image/{name}",
    description = "Fetch a public image",
    tag = "voting",
    params(
        ("name" = FileName, Path, description = "Name of the image"),
    ),
    responses(
        (status = OK, body = [u8], description = "The requested image"),
        (status = NOT_FOUND, description = "Image not found"),
    ),
)]
async fn fetch_voting_image(
    State(store): State<Arc<Store>>,
    axum::extract::Path(name): axum::extract::Path<FileName>,
    request: axum::http::Request<Body>,
) -> Result<impl IntoResponse, RestError> {
    let image = sea_entity::image::Entity::find_by_id(&name.0)
        .one(&store.db.sea)
        .await?;

    let Some(image) = image else {
        return Err(RestError::not_found("Image not found"));
    };

    serve_image(store, name, image.mime, request).await
}

#[utoipa::path(
    get,
    path = "/api/v/poll/{id}",
    description = "Fetch a public poll",
    tag = "voting",
    params(
        ("id" = IdString, Path, description = "Poll id"),
    ),
    responses(
        (status = OK, body = FetchVotingPoll, description = "The requested poll"),
        (status = NOT_FOUND, description = "Poll not found"),
    ),
)]
async fn fetch_voting_poll(
    State(store): State<Arc<Store>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let images = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::PollId.eq(&poll.id))
        .all(&store.db.sea)
        .await?;

    let aspect_ratios = images
        .iter()
        .map(|image| (image.id.clone(), image.aspect_ratio.clone()))
        .collect();

    Ok(Json(FetchVotingPoll {
        id: poll.id,
        title: poll.title,
        info: poll.info,
        ends: poll.ends,
        allowed_votes: poll.allowed_votes as u32,
        images: images.into_iter().map(|image| image.id).collect(),
        aspect_ratios,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v/poll/{id}/vote",
    description = "Vote on a poll",
    tag = "voting",
    params(
        ("id" = IdString, Path, description = "Poll id"),
    ),
    responses(
        (status = OK, body = FetchVotingPoll, description = "The requested vote"),
        (status = NOT_FOUND, description = "Poll or vote not found"),
    ),
)]
async fn fetch_vote(
    State(store): State<Arc<Store>>,
    Extension(eph_user): Extension<InjectedEphemeralUser>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let vote_entries = sea_entity::ephemeral_user_vote::Entity::find()
        .join(
            JoinType::InnerJoin,
            sea_entity::ephemeral_user_vote::Relation::Vote.def(),
        )
        .join(JoinType::InnerJoin, sea_entity::vote::Relation::Image.def())
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::ephemeral_user_vote::Column::EphemeralUserId.eq(eph_user.id))
                .add(sea_entity::image::Column::PollId.eq(&poll.id)),
        )
        .select_only()
        .columns(sea_entity::vote::Column::iter())
        .into_model::<sea_entity::vote::Model>()
        .all(&store.db.sea)
        .await?;

    if vote_entries.is_empty() {
        return Err(RestError::not_found("No votes found"));
    }

    let created = vote_entries[0].created_at;
    let votes = vote_entries.into_iter().map(|vote| vote.image_id).collect();

    Ok(Json(FetchVote { created, votes }))
}

#[utoipa::path(
    post,
    path = "/api/v/poll/{id}/vote",
    description = "Fetch a vote",
    tag = "voting",
    params(
        ("id" = IdString, Path, description = "Poll id"),
    ),
    responses(
        (status = OK, body = Vote, description = "Vote recorded"),
        (status = BAD_REQUEST, description = "Poll has ended or bad votes"),
        (status = NOT_FOUND, description = "Poll or vote not found"),
    ),
)]
async fn vote(
    State(store): State<Arc<Store>>,
    Extension(eph_user): Extension<InjectedEphemeralUser>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
    Json(vote): Json<Vote>,
) -> Result<impl IntoResponse, RestError> {
    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let now = now().as_secs_f64();

    if poll.ends < now {
        return Err(RestError::bad_req("Poll has ended"));
    }

    if vote.votes.is_empty() {
        return Err(RestError::bad_req("No votes provided"));
    }

    if vote.votes.len() > poll.allowed_votes as usize {
        return Err(RestError::bad_req("Too many votes"));
    }

    let previous_vote = sea_entity::ephemeral_user_vote::Entity::find()
        .join(
            JoinType::InnerJoin,
            sea_entity::ephemeral_user_vote::Relation::Vote.def(),
        )
        .join(JoinType::InnerJoin, sea_entity::vote::Relation::Image.def())
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::ephemeral_user_vote::Column::EphemeralUserId.eq(eph_user.id))
                .add(sea_entity::image::Column::PollId.eq(&poll.id)),
        )
        .one(&store.db.sea)
        .await?;

    if previous_vote.is_some() {
        return Err(RestError::bad_req("Already voted"));
    }

    for image_id in &vote.votes {
        let image = sea_entity::image::Entity::find_by_id(image_id)
            .one(&store.db.sea)
            .await?;

        if image.is_none() {
            return Err(RestError::bad_req("Invalid image"));
        }
    }

    transaction!(&store.db.sea, txn, {
        for image_id in vote.votes {
            let db_vote = sea_entity::vote::ActiveModel {
                image_id: Set(image_id.clone()),
                ..Default::default()
            }
            .insert(txn)
            .await?;

            sea_entity::ephemeral_user_vote::ActiveModel {
                vote_id: Set(db_vote.id),
                ephemeral_user_id: Set(eph_user.id),
                ..Default::default()
            }
            .insert(txn)
            .await?;
        }

        Ok(())
    })?;

    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v/poll/{id}/results",
    description = "Fetch results for a public poll",
    tag = "voting",
    params(
        ("id" = IdString, Path, description = "Poll id"),
    ),
    responses(
        (status = OK, body = FetchVoteResults, description = "The requested results"),
        (status = BAD_REQUEST, description = "Poll still active"),
        (status = FORBIDDEN, description = "Results not public"),
        (status = NOT_FOUND, description = "Poll or vote not found"),
    ),
)]
async fn fetch_voting_results(
    State(store): State<Arc<Store>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let now = now().as_secs_f64();

    if poll.ends > now {
        return Err(RestError::bad_req("Poll is still active"));
    }

    if !poll.results_public {
        return Err(RestError::forbidden("Results are not public"));
    }

    let images = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::PollId.eq(&poll.id))
        .find_with_related(sea_entity::vote::Entity)
        .all(&store.db.sea)
        .await?;

    let mut vote_counts = images
        .iter()
        .map(|(image, _)| (image.id.clone(), 0))
        .collect::<HashMap<_, u64>>();

    for vote in images.into_iter().flat_map(|(_, vote)| vote) {
        vote_counts.entry(vote.image_id).and_modify(|x| *x += 1);
    }

    let mut sorted_results = vote_counts.into_iter().collect::<Vec<_>>();
    sorted_results.sort_by(|a, b| b.1.cmp(&a.1));
    let sorted_results = sorted_results
        .into_iter()
        .map(|(id, _)| id)
        .collect::<Vec<_>>();

    if sorted_results.len() < 2 {
        return Err(RestError::internal("Unable to compute results"));
    }

    let first = sorted_results[0].clone();
    let second = sorted_results[1].clone();
    let third = sorted_results.get(2).cloned();
    let mut remaining = sorted_results.into_iter().skip(3).collect::<Vec<_>>();

    remaining.shuffle(&mut rng());

    Ok(Json(FetchVoteResults {
        id: poll.id,
        first,
        second,
        third,
        remaining,
    }))
}
