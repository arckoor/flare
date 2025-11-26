use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Extension, Json, Router, body::Body, extract::State, middleware, response::IntoResponse,
    routing,
};
use rand::{rng, seq::SliceRandom};
use sea_orm::{Iterable, JoinType, QuerySelect, Set, TransactionTrait, entity::prelude::*};

use crate::transaction;
use crate::{
    api::{
        api_params::{FetchVote, FetchVoteResults, FetchVotingPoll, FileName, IdString, Vote},
        error::RestError,
        middleware::{InjectedEphemeralUser, set_tracking_cookie},
        services::serve_image,
    },
    store::Store,
    time::now,
};

pub fn build_router(state: Arc<Store>) -> Router<Arc<Store>> {
    Router::new().nest(
        "/v",
        Router::new()
            .route("/image/{id}", routing::get(fetch_voting_image))
            .route("/poll/{id}", routing::get(fetch_voting_poll))
            .route("/poll/{id}/vote", routing::get(fetch_vote))
            .route("/poll/{id}/vote", routing::post(vote))
            .route("/poll/{id}/results", routing::get(fetch_voting_results))
            .layer(middleware::from_fn_with_state(state, set_tracking_cookie)),
    )
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
        (status = BAD_REQUEST, description = "Invalid file name"),
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
        (status = BAD_REQUEST, description = "Invalid poll id"),
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
        voting_limit: poll.voting_limit as u32,
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
        (status = OK, body = FetchVote, description = "The requested vote"),
        (status = BAD_REQUEST, description = "Invalid poll id"),
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
    request_body(content = Vote),
    params(
        ("id" = IdString, Path, description = "Poll id"),
    ),
    responses(
        (status = OK, description = "Vote recorded"),
        (status = BAD_REQUEST, description = "Poll has ended or bad votes"),
        (status = NOT_FOUND, description = "Poll or vote not found"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
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

    if vote.votes.len() > poll.voting_limit as usize {
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
        .collect::<HashMap<_, usize>>();

    for vote in images.into_iter().flat_map(|(_, vote)| vote) {
        vote_counts.entry(vote.image_id).and_modify(|x| *x += 1);
    }

    let mut sorted_results = vote_counts.into_iter().collect::<Vec<_>>();
    sorted_results.sort_by(|a, b| b.1.cmp(&a.1));

    if sorted_results.len() < 2 {
        return Err(RestError::internal("Unable to compute results"));
    }

    let mut vote_cnt = sorted_results[0].1;
    let mut vote_idx = 0;
    let mut first = Vec::new();
    let mut second = Vec::new();
    let mut third = Vec::new();
    let mut remaining = Vec::new();
    for (image, cnt) in sorted_results {
        if vote_idx < 3 && cnt != vote_cnt {
            vote_idx += 1;
            vote_cnt = cnt;
        }

        [&mut first, &mut second, &mut third, &mut remaining][vote_idx].push(image);
    }
    remaining.shuffle(&mut rng());

    Ok(Json(FetchVoteResults {
        id: poll.id,
        first,
        second,
        third,
        remaining,
    }))
}
