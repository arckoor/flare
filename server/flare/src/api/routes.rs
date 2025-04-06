use std::collections::{HashMap, HashSet};
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
use hyper::{StatusCode, header};
use rand::{rng, seq::SliceRandom};
use sea_entity::sea_orm_active_enums::Permissions;
use sea_orm::{IntoActiveModel, QueryOrder, Set, TransactionTrait, entity::prelude::*};
use sea_orm::{Iterable, QuerySelect};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{requires, store::Store, transaction, validate_text};

use super::api_params::{
    AddGroup, AddImage, AddPoll, AddedPoll, EditGroup, EditPoll, FetchPoll, FetchPolls,
    FetchResults, FetchVote, FetchVoteResults, FetchVotingPoll, FileName, Group, Member,
    OAuthCallback, OAuthLogin, PaginatedPoll, Paginator, PublishResults, TokenResponse,
    UploadedImage, Vote,
};
use super::error::{FoundError, RestError};
use super::middleware::InjectedEphemeralUser;
use super::middleware::set_tracking_cookie;
use super::openapi::ApiDoc;
use super::services::serve_image;
use super::validation::{inspect_validate_image, validate_paginator, validate_user_text};

#[cfg(feature = "sim")]
use super::api_params::LoginInfo;

pub fn build_router(state: Arc<Store>) -> Router {
    let router = Router::new()
        .route("/ping", routing::get(ping))
        .route("/auth-ping", routing::get(auth_ping))
        .route("/oauth/{provider}/login", routing::get(oauth_login))
        .route("/oauth/{provider}/callback", routing::get(oauth_callback))
        .route("/logout", routing::get(logout))
        .route("/refresh", routing::get(refresh))
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
        .route("/poll/{id}/results", routing::get(fetch_results))
        .route("/poll/{id}/results", routing::post(publish_results))
        .route("/group/{id}", routing::post(join_group))
        .route("/group/{id}", routing::delete(leave_group))
        .route("/groups", routing::post(add_group))
        .route("/groups/{id}", routing::get(fetch_group))
        .route("/groups/{id}", routing::patch(edit_group))
        .route("/groups/{id}", routing::delete(remove_group))
        .route("/groups/{id}/user/{user_id}", routing::post(add_group_user))
        .route(
            "/groups/{id}/user/{user_id}",
            routing::delete(remove_group_user),
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

    let router = router
        .with_state(state)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()));

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
    get,
    path = "/api/ping",
    responses(
        (status = OK, description = "Pong"),
    )
))]
async fn ping() -> impl IntoResponse {
    "Pong"
}

#[cfg_attr(feature = "api-doc", utoipa::path(
    get,
    path = "/api/auth-ping",
    responses(
        (status = OK, description = "Pong"),
        (status = UNAUTHORIZED, description = "Unauthorized"),
    )
))]
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
            permissions: Set(vec![Permissions::ManageGroups, Permissions::ManagePolls]),
            ..Default::default()
        }
        .insert(&store.db.sea)
        .await?;

        let (access, jar) = store.jwt.login(&user, jar).await?;
        return Ok((jar, Json(TokenResponse { access })));
    }
}

async fn oauth_login(
    State(store): State<Arc<Store>>,
    axum::extract::Path(provider): axum::extract::Path<String>,
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

    let url = match provider.as_str() {
        "discord" => store
            .oauth
            .discord
            .auth_url(redirect_uri, existing_user)
            .await?
            .to_string(),
        "github" => store
            .oauth
            .github
            .auth_url(redirect_uri, existing_user)
            .await?
            .to_string(),
        _ => return Err(FoundError::new(store.oauth.login_url(), "".to_string())),
    };

    Ok((StatusCode::FOUND, [(header::LOCATION, url.to_string())]))
}

async fn oauth_callback(
    State(store): State<Arc<Store>>,
    axum::extract::Path(provider): axum::extract::Path<String>,
    query: Result<Query<OAuthCallback>, QueryRejection>,
    jar: CookieJar,
) -> Result<impl IntoResponse, FoundError> {
    let (code, state) = match query {
        Ok(query) => (query.code.clone(), query.state.clone()),
        Err(_) => return Err(FoundError::new(store.oauth.login_url(), "".to_string())),
    };

    let ((oauth_id, redirect_uri, existing_user), provider) = match provider.as_str() {
        "discord" => (
            store.oauth.discord.callback(code, state).await?,
            sea_entity::sea_orm_active_enums::OauthProvider::Discord,
        ),

        "github" => (
            store.oauth.github.callback(code, state).await?,
            sea_entity::sea_orm_active_enums::OauthProvider::Github,
        ),
        _ => {
            return Err(FoundError::new(
                store.oauth.login_url(),
                "Invalid provider".to_string(),
            ));
        }
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

async fn logout(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;
    let jar = store.jwt.revoke(&claims.sub, jar).await?;

    Ok((StatusCode::NO_CONTENT, jar))
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
    path = "/api/image",
    request_body(content = inline(AddImage), description = "Multipart file", content_type = "multipart/form-data"),
    responses(
        (status = OK, body = UploadedImage, description = "Image uploaded"),
        (status = BAD_REQUEST, description = "Invalid content type or no file provided"),
        (status = INTERNAL_SERVER_ERROR, description = "Failed to create image or error executing query"),
    ),
    security(("bearer-auth" = []))
))]
async fn add_image(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| RestError::bad_req("Failed to parse multipart"))?
    else {
        return Err(RestError::bad_req("No file provided"));
    };

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

    let aspect_ratio = inspect_validate_image(&data, content_type)?;

    let filename = format!("{}.{}", cuid2::create_id(), extension);
    let path = store.image_path.join(&filename);

    let mut file = tokio::fs::File::create_new(&path)
        .await
        .map_err(|_| RestError::internal("Failed to create file"))?;

    tokio::io::copy(&mut &*data, &mut file)
        .await
        .map_err(|_| RestError::internal("Failed to write to file"))?;

    sea_entity::image::ActiveModel {
        id: Set(filename.clone()),
        aspect_ratio: Set(aspect_ratio),
        user_id: Set(claims.sub.clone()),
        ..Default::default()
    }
    .insert(&store.db.sea)
    .await?;

    Ok(Json(UploadedImage { name: filename }))
}

pub async fn fetch_image(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(name): axum::extract::Path<FileName>,
    request: axum::http::Request<Body>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;
    let image = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::Id.eq(&name.0))
        .find_also_related(sea_entity::poll::Entity)
        .one(&store.db.sea)
        .await?;

    let Some((image, poll)) = image else {
        return Err(RestError::not_found("Image not found"));
    };

    if !(image.user_id == claims.sub
        || poll
            .as_ref()
            .and_then(|p| p.group_id.clone())
            .is_some_and(|group_id| claims.groups.contains(&group_id)))
    {
        return Err(RestError::forbidden(
            "You are not authorized to view this image",
        ));
    }

    serve_image(store, name, request).await
}

pub async fn remove_image(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(name): axum::extract::Path<FileName>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let image = sea_entity::image::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::image::Column::Id.eq(&name.0))
                .add(sea_entity::image::Column::UserId.eq(&claims.sub))
                .add(sea_entity::image::Column::PollId.is_null()),
        )
        .one(&store.db.sea)
        .await?;

    if image.is_none() {
        return Err(RestError::not_found("Image not found"));
    }

    let path = store.image_path.join(&name);
    if !path.exists() {
        return Err(RestError::not_found("Image not found"));
    }

    tokio::fs::remove_file(path)
        .await
        .map_err(|_| RestError::internal("Failed to remove file"))?;

    sea_entity::image::Entity::delete_by_id(&name.0)
        .exec(&store.db.sea)
        .await?;

    Ok(())
}

pub async fn fetch_polls(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    group_id: Option<axum::extract::Path<String>>,
    Query(paginator): Query<Paginator>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    validate_paginator(&paginator, 50)?;

    let pager = {
        let query = sea_entity::poll::Entity::find()
            .filter(store.db.filter_polls(
                &claims.sub,
                claims.groups.clone(),
                group_id.map(|group_id| group_id.0),
            ))
            .order_by(
                // TODO would be nice to be able to sort by different columns
                sea_entity::poll::Column::CreatedAt,
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
        let votes = sea_entity::vote::Entity::find()
            .filter(sea_entity::vote::Column::PollId.eq(&poll.id))
            .count(&store.db.sea)
            .await?;

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

pub async fn add_poll(
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
            owner_id: Set(claims.sub.clone()),
            ..Default::default()
        }
        .insert(txn)
        .await?;

        let res = sea_entity::image::Entity::update_many()
            .col_expr(
                sea_entity::image::Column::PollId,
                Expr::value(poll.id.clone()),
            )
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::image::Column::Id.is_in(add_poll.images.clone()))
                    .add(sea_entity::image::Column::UserId.eq(claims.sub.clone()))
                    .add(sea_entity::image::Column::PollId.is_null()),
            )
            .exec(txn)
            .await?;

        if res.rows_affected != add_poll.images.len() as u64 {
            return Err(RestError::bad_req("Invalid images"));
        }

        Ok(Json(AddedPoll { id: poll.id }))
    })
}

pub async fn fetch_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let poll = sea_entity::poll::Entity::find()
        .filter(
            store
                .db
                .filter_poll_by_id(&id, &claims.sub, claims.groups.clone()),
        )
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let images = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::PollId.eq(&poll.id))
        .all(&store.db.sea)
        .await?;

    let votes = sea_entity::vote::Entity::find()
        .filter(sea_entity::vote::Column::PollId.eq(&poll.id))
        .count(&store.db.sea)
        .await?;

    // TODO we store the image aspect ratio, but it's not used here?
    Ok(Json(FetchPoll {
        id: poll.id,
        title: poll.title,
        info: poll.info,
        ends: poll.ends,
        allowed_votes: poll.allowed_votes as u32,
        images: images.into_iter().map(|image| image.id).collect(),
        votes,
    }))
}

pub async fn edit_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(edit_poll): Json<EditPoll>,
) -> Result<impl IntoResponse, RestError> {
    // TODO this function is too long.
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let poll = sea_entity::poll::Entity::find()
        .filter(
            store
                .db
                .filter_poll_by_id(&id, &claims.sub, claims.groups.clone()),
        )
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let current_images = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::PollId.eq(&id))
        .count(&store.db.sea)
        .await?;

    let new_image_count = current_images
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

    transaction!(&store.db.sea, txn, {
        let mut poll = poll.into_active_model();

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
            let res = sea_entity::image::Entity::update_many()
                .col_expr(sea_entity::image::Column::PollId, Expr::value(id.clone()))
                .filter(
                    sea_orm::Condition::all()
                        .add(sea_entity::image::Column::Id.is_in(add_images.clone()))
                        .add(sea_entity::image::Column::UserId.eq(claims.sub.clone()))
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
                        .add(sea_entity::image::Column::PollId.eq(id.clone())),
                )
                .exec(txn)
                .await?;

            sea_entity::vote::Entity::delete_many()
                .filter(
                    sea_orm::Condition::all()
                        .add(sea_entity::vote::Column::ImageId.is_in(remove_images.clone()))
                        .add(sea_entity::vote::Column::PollId.eq(id.clone())),
                )
                .exec(txn)
                .await?;

            if res.rows_affected != remove_images.len() as u64 {
                return Err(RestError::bad_req("Invalid remove images"));
            }
        }

        // Todo is this check really necessary?
        let images = sea_entity::image::Entity::find()
            .filter(sea_entity::image::Column::PollId.eq(&id))
            .all(txn)
            .await?;

        if images.len() as u64 != new_image_count {
            return Err(RestError::bad_req("Invalid image count"));
        }

        poll.update(txn).await?;

        Ok(())
    })?;

    if let Some(remove_images) = edit_poll.remove_images {
        for image in remove_images {
            let path = store.image_path.join(&image);
            if !path.exists() {
                // todo these can maybe be soft fails
                return Err(RestError::internal(""));
            }

            tokio::fs::remove_file(path)
                .await
                .map_err(|_| RestError::internal("Failed to remove file"))?;
        }
    }

    Ok(())
}

pub async fn remove_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let poll = sea_entity::poll::Entity::find()
        .filter(
            store
                .db
                .filter_poll_by_id(&id, &claims.sub, claims.groups.clone()),
        )
        .one(&store.db.sea)
        .await?;

    if poll.is_none() {
        return Err(RestError::not_found("Poll not found"));
    }

    let poll_images = transaction!(&store.db.sea, txn, {
        let poll_images = sea_entity::image::Entity::find()
            .filter(sea_entity::image::Column::PollId.eq(&id))
            .all(txn)
            .await?
            .iter()
            .map(|image| image.id.clone())
            .collect::<Vec<_>>();

        sea_entity::image::Entity::delete_many()
            .filter(sea_entity::image::Column::PollId.eq(&id))
            .exec(txn)
            .await?;

        sea_entity::poll::Entity::delete_by_id(&id)
            .exec(txn)
            .await?;

        Ok(poll_images)
    })?;

    for image in poll_images {
        let path = store.image_path.join(&image);
        if !path.exists() {
            // TODO no
            // if we're here, the db entry is already gone, so just fail silently
            // old / expired images will need to be cleaned anyway at some point
            return Err(RestError::not_found("Image not found"));
        }

        tokio::fs::remove_file(path)
            .await
            .map_err(|_| RestError::internal("Failed to remove file"))?;
    }

    Ok(())
}

pub async fn fetch_results(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    // TODO this can be much more extensive, e.g. histograms, ...
    // also 3 db queries :/

    let poll = sea_entity::poll::Entity::find()
        .filter(
            store
                .db
                .filter_poll_by_id(&id, &claims.sub, claims.groups.clone()),
        )
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let now = Store::now()?.as_secs_f64();

    let images = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::PollId.eq(&id))
        .all(&store.db.sea)
        .await?;

    let mut results = images
        .into_iter()
        .map(|img| (img.id.clone(), 0))
        .collect::<HashMap<_, u64>>();

    let votes = sea_entity::vote::Entity::find()
        .filter(sea_entity::vote::Column::PollId.eq(&id))
        .all(&store.db.sea)
        .await?;

    for vote in votes {
        results.entry(vote.image_id).and_modify(|v| *v += 1);
    }

    Ok(Json(FetchResults {
        id: poll.id,
        votes: results,
        public: poll.results_public,
        ended: poll.ends < now,
    }))
}

pub async fn publish_results(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(publish_results): Json<PublishResults>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let poll = sea_entity::poll::Entity::find()
        .filter(
            store
                .db
                .filter_poll_by_id(&id, &claims.sub, claims.groups.clone()),
        )
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let now = Store::now()?.as_secs_f64();

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
    poll.save(&store.db.sea).await?;

    Ok(())
}

pub async fn join_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    // TODO this currently assumes the invite link is shared out-of-band
    // available invites could also be shown to the user directly, but should include enough information
    // to uniquely identify the group the user would be joining

    if sea_entity::group_join_request::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::group_join_request::Column::GroupId.eq(&id))
                .add(sea_entity::group_join_request::Column::UserId.eq(&claims.sub)),
        )
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("Invite not found"));
    }

    let user_id = claims.sub.clone();
    transaction!(&store.db.sea, txn, {
        sea_entity::group_user::ActiveModel {
            group_id: Set(id.clone()),
            user_id: Set(user_id.clone()),
            ..Default::default()
        }
        .insert(txn)
        .await?;

        sea_entity::group_join_request::Entity::delete_by_id((id.clone(), user_id.clone()))
            .exec(txn)
            .await?;
        Ok(())
    })?;

    store.jwt.revoke_access(&claims.sub).await?;

    Ok(())
}

pub async fn leave_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    if sea_entity::group_user::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::group_user::Column::GroupId.eq(&id))
                .add(sea_entity::group_user::Column::UserId.eq(&claims.sub)),
        )
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("Group not found"));
    }

    let group = sea_entity::group::Entity::find()
        .filter(sea_entity::group::Column::Id.eq(&id))
        .one(&store.db.sea)
        .await?;

    let Some(group) = group else {
        // group users should always cascade delete
        return Err(RestError::internal("Group not found"));
    };

    let user_id = claims.sub.clone();
    transaction!(&store.db.sea, txn, {
        sea_entity::group_user::Entity::delete_by_id((id.clone(), user_id.clone()))
            .exec(txn)
            .await?;

        sea_entity::poll::Entity::update_many()
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::poll::Column::OwnerId.eq(&user_id))
                    .add(sea_entity::poll::Column::GroupId.eq(&id)),
            )
            .col_expr(
                sea_entity::poll::Column::OwnerId,
                Expr::value(group.owner_id.clone()),
            )
            .exec(txn)
            .await?;

        Ok(())
    })?;

    store.jwt.revoke_access(&claims.sub).await?;

    Ok(())
}

pub async fn add_group(
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

    Ok(Json(Group {
        id: group.id,
        name: group.name,
        owner: claims.sub.clone(),
        members: vec![Member { id: claims.sub }],
    }))
}

pub async fn fetch_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let group = sea_entity::group::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::group::Column::Id.eq(&id))
                .add(
                    sea_orm::Condition::any()
                        .add(sea_entity::group::Column::OwnerId.eq(&claims.sub))
                        .add(sea_entity::group::Column::Id.is_in(claims.groups.clone())),
                ),
        )
        .one(&store.db.sea)
        .await?;

    let Some(group) = group else {
        return Err(RestError::not_found("Group not found"));
    };

    let group_users = sea_entity::group_user::Entity::find()
        .filter(sea_entity::group_user::Column::GroupId.eq(&id))
        .all(&store.db.sea)
        .await?;

    Ok(Json(Group {
        id: group.id,
        name: group.name,
        owner: group.owner_id,
        members: group_users
            .into_iter()
            .map(|group_user| Member {
                id: group_user.user_id,
            })
            .collect(),
    }))
}

pub async fn edit_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(edit_group): Json<EditGroup>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManageGroups)?;

    let group = sea_entity::group::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::group::Column::Id.eq(id.clone()))
                .add(sea_entity::group::Column::OwnerId.eq(&claims.sub)),
        )
        .one(&store.db.sea)
        .await?;

    let Some(group) = group else {
        return Err(RestError::not_found("Group not found"));
    };

    transaction!(store.db.sea, txn, {
        let mut group = group.into_active_model();

        if let Some(name) = edit_group.name {
            validate_text!(&name);
            group.name = Set(name);
        }

        if let Some(owner_id) = edit_group.owner {
            if owner_id == claims.sub {
                return Err(RestError::bad_req("You already own this group"));
            }

            let group_user = sea_entity::group_user::Entity::find()
                .filter(
                    sea_orm::Condition::all()
                        .add(sea_entity::group_user::Column::GroupId.eq(id))
                        .add(sea_entity::group_user::Column::UserId.eq(&owner_id)),
                )
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

        group.update(txn).await?;

        Ok(())
    })?;

    Ok(())
}

pub async fn remove_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManageGroups)?;

    let group = sea_entity::group::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::group::Column::Id.eq(id.clone()))
                .add(sea_entity::group::Column::OwnerId.eq(&claims.sub)),
        )
        .one(&store.db.sea)
        .await?;

    let Some(_) = group else {
        return Err(RestError::not_found("Group not found"));
    };

    let group_users = sea_entity::group_user::Entity::find()
        .filter(sea_entity::group_user::Column::GroupId.eq(&id))
        .all(&store.db.sea)
        .await?;

    transaction!(&store.db.sea, txn, {
        sea_entity::group_user::Entity::delete_many()
            .filter(sea_entity::group_user::Column::GroupId.eq(id.clone()))
            .exec(txn)
            .await?;

        sea_entity::group::Entity::delete_by_id(&id)
            .exec(txn)
            .await?;

        // todo figure out if we want to delete associated polls or not
        // maybe a with_delete option?

        Ok(())
    })?;

    for user in group_users {
        store.jwt.revoke_access(&user.user_id).await?;
    }

    Ok(())
}

pub async fn add_group_user(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path((id, user_id)): axum::extract::Path<(String, String)>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManageGroups)?;

    if sea_entity::group::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::group::Column::Id.eq(&id))
                .add(sea_entity::group::Column::OwnerId.eq(&claims.sub)),
        )
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("Group not found"));
    }

    if sea_entity::user::Entity::find_by_id(&user_id)
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("User not found"));
    }

    if sea_entity::group_user::Entity::find_by_id((id.clone(), user_id.clone()))
        .one(&store.db.sea)
        .await?
        .is_some()
    {
        return Err(RestError::bad_req("User already in group"));
    }

    let inner_user_id = user_id.clone();
    transaction!(store.db.sea, txn, {
        sea_entity::group_join_request::ActiveModel {
            group_id: Set(id),
            user_id: Set(inner_user_id),
            ..Default::default()
        }
        .insert(txn)
        .await?;

        Ok(())
    })?;

    Ok(())
}

pub async fn remove_group_user(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path((id, user_id)): axum::extract::Path<(String, String)>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManageGroups)?;

    if claims.sub == user_id {
        return Err(RestError::bad_req(
            "You cannot remove yourself from the group",
        ));
    }

    if sea_entity::group::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::group::Column::Id.eq(&id))
                .add(sea_entity::group::Column::OwnerId.eq(&claims.sub)),
        )
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("Group not found"));
    }

    if sea_entity::group_user::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::group_user::Column::GroupId.eq(&id))
                .add(sea_entity::group_user::Column::UserId.eq(&user_id)),
        )
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::not_found("User not in group"));
    }

    let inner_user_id = user_id.clone();
    transaction!(&store.db.sea, txn, {
        sea_entity::group_user::Entity::delete_by_id((id.clone(), inner_user_id.clone()))
            .exec(txn)
            .await?;

        sea_entity::poll::Entity::update_many()
            .col_expr(sea_entity::poll::Column::OwnerId, Expr::value(claims.sub))
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::poll::Column::OwnerId.eq(inner_user_id.clone()))
                    .add(sea_entity::poll::Column::GroupId.eq(id)),
            )
            .exec(txn)
            .await?;

        Ok(())
    })?;

    store.jwt.revoke_access(&user_id).await?;

    Ok(())
}

pub async fn fetch_voting_image(
    State(store): State<Arc<Store>>,
    axum::extract::Path(name): axum::extract::Path<FileName>,
    request: axum::http::Request<Body>,
) -> Result<impl IntoResponse, RestError> {
    let image = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::Id.eq(&name.0))
        .one(&store.db.sea)
        .await?;

    if image.is_none() {
        return Err(RestError::not_found("Image not found"));
    }

    serve_image(store, name, request).await
}

pub async fn fetch_voting_poll(
    State(store): State<Arc<Store>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let poll = sea_entity::poll::Entity::find()
        .filter(sea_entity::poll::Column::Id.eq(id))
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let images = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::PollId.eq(&poll.id))
        .all(&store.db.sea)
        .await?;

    Ok(Json(FetchVotingPoll {
        id: poll.id,
        title: poll.title,
        info: poll.info,
        ends: poll.ends,
        allowed_votes: poll.allowed_votes as u32,
        images: images.into_iter().map(|image| image.id).collect(),
    }))
}

pub async fn fetch_vote(
    State(store): State<Arc<Store>>,
    Extension(eph_user): Extension<InjectedEphemeralUser>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let poll = sea_entity::poll::Entity::find()
        .filter(sea_entity::poll::Column::Id.eq(id))
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let vote_entries = sea_entity::ephemeral_user_vote::Entity::find()
        .inner_join(sea_entity::vote::Entity)
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::ephemeral_user_vote::Column::EphemeralUserId.eq(eph_user.id))
                .add(sea_entity::vote::Column::PollId.eq(&poll.id)),
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

pub async fn vote(
    State(store): State<Arc<Store>>,
    Extension(eph_user): Extension<InjectedEphemeralUser>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(vote): Json<Vote>,
) -> Result<impl IntoResponse, RestError> {
    let poll = sea_entity::poll::Entity::find()
        .filter(sea_entity::poll::Column::Id.eq(id))
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let now = Store::now()?.as_secs_f64();

    if poll.ends < now {
        return Err(RestError::bad_req("Poll has ended"));
    }

    if vote.votes.is_empty() {
        return Err(RestError::bad_req("No votes provided"));
    }

    let unique_votes = vote.votes.clone().into_iter().collect::<HashSet<_>>();

    if unique_votes.len() > poll.allowed_votes as usize {
        return Err(RestError::bad_req("Too many votes"));
    }

    let previous_vote = sea_entity::ephemeral_user_vote::Entity::find()
        .inner_join(sea_entity::vote::Entity)
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::ephemeral_user_vote::Column::EphemeralUserId.eq(eph_user.id))
                .add(sea_entity::vote::Column::PollId.eq(&poll.id)),
        )
        .one(&store.db.sea)
        .await?;

    if previous_vote.is_some() {
        return Err(RestError::bad_req("Already voted"));
    }

    for image_id in &unique_votes {
        let image = sea_entity::image::Entity::find()
            .filter(sea_entity::image::Column::Id.eq(image_id))
            .one(&store.db.sea)
            .await?;

        if image.is_none() {
            return Err(RestError::bad_req("Invalid image"));
        }
    }

    transaction!(&store.db.sea, txn, {
        for image_id in unique_votes {
            let db_vote = sea_entity::vote::ActiveModel {
                poll_id: Set(poll.id.clone()),
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

pub async fn fetch_voting_results(
    State(store): State<Arc<Store>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, RestError> {
    let poll = sea_entity::poll::Entity::find()
        .filter(sea_entity::poll::Column::Id.eq(id))
        .one(&store.db.sea)
        .await?;

    let Some(poll) = poll else {
        return Err(RestError::not_found("Poll not found"));
    };

    let now = Store::now()?.as_secs_f64();

    if poll.ends > now {
        return Err(RestError::bad_req("Poll is still active"));
    }

    if !poll.results_public {
        return Err(RestError::forbidden("Results are not public"));
    }

    let images = sea_entity::image::Entity::find()
        .filter(sea_entity::image::Column::PollId.eq(&poll.id))
        .all(&store.db.sea)
        .await?;

    let mut vote_counts = images
        .into_iter()
        .map(|img| (img.id.clone(), 0))
        .collect::<HashMap<_, u64>>();

    let votes = sea_entity::vote::Entity::find()
        .filter(sea_entity::vote::Column::PollId.eq(&poll.id))
        .all(&store.db.sea)
        .await?;

    for vote in votes {
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
