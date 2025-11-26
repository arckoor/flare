use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use sea_entity::sea_orm_active_enums::Permissions;
use sea_orm::{
    IntoActiveModel, Iterable, JoinType, QueryOrder, QuerySelect, Set, TransactionTrait,
    entity::prelude::*, sea_query,
};

use crate::{
    api::{
        api_params::{
            AddPoll, AddScheduledPoll, ApproveScheduledPollSubmission, EditPoll, EditScheduledPoll,
            EditScheduledPollSubmission, FetchPoll, FetchPollSort, FetchPolls, FetchResults,
            FetchScheduledPoll, FetchScheduledPollSort, FetchScheduledPollSubmission,
            FetchScheduledPollSubmissions, FetchScheduledPolls, IdString, PaginatedPoll, Paginator,
            PublishResults, ScheduledPollSubmission, UpdatedPoll,
        },
        error::RestError,
        services::remove_file,
        validation::{
            MAX_INFO_LEN, MAX_NAME_LEN, MAX_TITLE_LEN, validate_paginator, validate_text,
        },
    },
    db::Database,
    store::Store,
    tasks::Scheduler,
    time::{find_next_run, now},
};
use crate::{requires, transaction};

pub fn build_router() -> Router<Arc<Store>> {
    Router::new() // we unfortunately need to duplicate the endpoint because otherwise you'd need to include the trailing slash in the url
        .route("/polls", routing::get(fetch_polls))
        .route("/polls/{group_id}", routing::get(fetch_polls))
        .route("/poll", routing::post(add_poll))
        .route("/poll/{id}", routing::get(fetch_poll))
        .route("/poll/{id}", routing::patch(edit_poll))
        .route("/poll/{id}", routing::delete(remove_poll))
        .route("/poll/{id}/{group_id}", routing::patch(add_poll_to_group))
        .route("/poll/{id}/results", routing::get(fetch_results))
        .route("/poll/{id}/results", routing::post(publish_results))
        .route("/scheduled-polls", routing::get(fetch_scheduled_polls))
        .route(
            "/scheduled-polls/{group_id}",
            routing::get(fetch_scheduled_polls),
        )
        .route("/scheduled-poll", routing::post(add_scheduled_poll))
        .route("/scheduled-poll/{id}", routing::get(fetch_scheduled_poll))
        .route("/scheduled-poll/{id}", routing::patch(edit_scheduled_poll))
        .route(
            "/scheduled-poll/{id}",
            routing::delete(remove_scheduled_poll),
        )
        .route(
            "/scheduled-poll/{id}/submissions",
            routing::get(fetch_scheduled_poll_submissions),
        )
        .route(
            "/scheduled-poll/{id}/approve",
            routing::patch(approve_scheduled_poll_submission),
        )
        .route(
            "/scheduled-poll/{id}/submit",
            routing::get(fetch_scheduled_poll_submission),
        )
        .route(
            "/scheduled-poll/{id}/submit",
            routing::patch(edit_scheduled_poll_submission),
        )
}

// utoipa makes (Option<T>, Path) parameters required, so we're stuck with this
#[utoipa::path(
    get,
    path = "/api/polls",
    description = "Fetch a number of polls",
    tag = "polls",
    params(
        ("page" = Option<u64>, Query, minimum = 0),
        ("page_size"  = Option<u64>, Query, minimum = 1, maximum = 50),
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
        ("group_id" = IdString, Path, description = "Group id to filter by"),
        ("page" = Option<u64>, Query, minimum = 0),
        ("page_size"  = Option<u64>, Query, minimum = 1, maximum = 50),
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
    group_id: Option<axum::extract::Path<IdString>>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    // TODO would be cool to be able to filter by no-groups, e.g. "private" polls too

    validate_paginator(&paginator, 50)?;

    let pager = sea_entity::poll::Entity::find()
        .filter(Database::filter_polls(
            &claims.sub,
            claims.groups.clone(),
            group_id.map(|group_id| group_id.0.0),
            false,
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
        )
        .paginate(&store.db.sea, paginator.page_size);

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
        (status = NOT_FOUND, description = "Group not found"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
    ),
    security(("ac-manage-polls" = [])),
)]
async fn add_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(add_poll): Json<AddPoll>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    if add_poll.images.len() < 2 {
        return Err(RestError::bad_req("Not enough images provided"));
    }

    match add_poll.voting_limit {
        0 => return Err(RestError::bad_req("Voting limit must be greater than 0")),
        amount if amount > add_poll.images.len() as u32 => {
            return Err(RestError::bad_req("Voting limit exceeds image count"));
        }
        _ => {}
    }

    if let Some(group) = &add_poll.group
        && !claims.groups.contains(&group.0)
    {
        return Err(RestError::not_found("Group not found"));
    }

    if add_poll.ends < 0.0 {
        return Err(RestError::bad_req("Ends must be positive"));
    }

    validate_text(&add_poll.title, false, MAX_TITLE_LEN)?;
    validate_text(&add_poll.info, true, MAX_INFO_LEN)?;

    let short_link = cuid2::slug();

    transaction!(&store.db.sea, txn, {
        let poll = sea_entity::poll::ActiveModel {
            id: Set(short_link.clone()),
            title: Set(add_poll.title.clone()),
            info: Set(add_poll.info.clone()),
            ends: Set(add_poll.ends),
            voting_limit: Set(add_poll
                .voting_limit
                .try_into()
                .map_err(|_| RestError::bad_req("Invalid voting limit"))?),
            owner_id: Set(if add_poll.group.is_some() {
                None
            } else {
                Some(claims.sub.clone())
            }),
            group_id: Set(add_poll.group.clone().map(|g| g.0)),
            ..Default::default()
        }
        .insert(txn)
        .await?;

        let images = {
            let mut stmt = sea_entity::image::Entity::update_many().col_expr(
                sea_entity::image::Column::PollId,
                Expr::value(poll.id.clone()),
            );
            if let Some(group_id) = add_poll.group {
                stmt = stmt
                    .col_expr(
                        sea_entity::image::Column::OwnerId,
                        Expr::value(None::<String>),
                    )
                    .col_expr(
                        sea_entity::image::Column::GroupId,
                        Expr::value(Some(group_id.0.clone())),
                    );
            }

            stmt
        }
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::image::Column::Id.is_in(add_poll.images.clone()))
                .add(sea_entity::image::Column::OwnerId.eq(claims.sub.clone()))
                .add(sea_entity::image::Column::PollId.is_null())
                .add(
                    sea_entity::image::Column::Id.not_in_subquery(
                        sea_query::Query::select()
                            .from(sea_entity::scheduled_image::Entity)
                            .column(sea_entity::scheduled_image::Column::ImageId)
                            .to_owned(),
                    ),
                ),
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

        // todo why do we answer with OK instead of CREATED here (and everywhere else??)
        Ok(Json(FetchPoll {
            id: poll.id,
            title: poll.title,
            info: poll.info,
            ends: poll.ends,
            voting_limit: poll.voting_limit as u32,
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
        (status = BAD_REQUEST, description = "Invalid poll id"),
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

    let Some(poll) = sea_entity::poll::Entity::find_by_id(&id.0)
        .filter(Database::filter_polls(
            &claims.sub,
            claims.groups.clone(),
            None,
            true,
        ))
        .one(&store.db.sea)
        .await?
    else {
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
        voting_limit: poll.voting_limit as u32,
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
    request_body(content = EditPoll, description = "The fields to change"),
    params(
        ("id" = IdString, Path, description = "The poll id")
    ),
    responses(
        (status = OK, body = FetchPoll, description = "The updated poll"),
        (status = BAD_REQUEST, description = "Bad options provided"),
        (status = FORBIDDEN, description = "Poll is locked"),
        (status = NOT_FOUND, description = "Poll not found"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
    ),
    security(("ac-manage-polls" = [])),
)]
async fn edit_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
    Json(edit_poll): Json<EditPoll>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManagePolls)?;

    let poll = sea_entity::poll::Entity::find_by_id(&id.0)
        .filter(Database::filter_polls(
            &claims.sub,
            claims.groups.clone(),
            None,
            false,
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

    if let Some(ends) = edit_poll.ends
        && ends < 0.0
    {
        return Err(RestError::bad_req("Ends must be positive"));
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

    let voting_limit = edit_poll.voting_limit.unwrap_or(poll.voting_limit as u32);

    if voting_limit as u64 > new_image_count {
        return Err(RestError::bad_req("Voting limit exceed image count"));
    }

    let remove_images = edit_poll.remove_images.clone();
    let poll_id = poll.id.clone();
    let group_id = poll.group_id.clone();

    let (poll, images) = transaction!(&store.db.sea, txn, {
        let mut poll = poll.into_active_model();

        poll.title.reset();

        if let Some(title) = edit_poll.title {
            validate_text(&title, false, MAX_TITLE_LEN)?;
            poll.title = Set(title);
        }

        if let Some(info) = edit_poll.info {
            validate_text(&info, false, MAX_INFO_LEN)?;
            poll.info = Set(info);
        }

        if let Some(ends) = edit_poll.ends {
            poll.ends = Set(ends);
        }

        if let Some(voting_limit) = edit_poll.voting_limit {
            poll.voting_limit = Set(voting_limit as i32);
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
                    .add(sea_entity::image::Column::PollId.is_null())
                    .add(
                        sea_entity::image::Column::Id.not_in_subquery(
                            sea_query::Query::select()
                                .from(sea_entity::scheduled_image::Entity)
                                .column(sea_entity::scheduled_image::Column::ImageId)
                                .to_owned(),
                        ),
                    ),
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

        let images = sea_entity::image::Entity::find()
            .filter(sea_entity::image::Column::PollId.eq(&id.0))
            .find_with_related(sea_entity::vote::Entity)
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

        Ok((poll, images))
    })?;

    if let Some(remove_images) = edit_poll.remove_images {
        for image in remove_images {
            let path = store.image_path.join(&image);
            remove_file(&path, &image).await;
        }
    }

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
        voting_limit: poll.voting_limit as u32,
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
        (status = BAD_REQUEST, description = "Invalid poll id"),
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
            false,
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
    request_body(content = UpdatedPoll),
    params(
        ("id" = IdString, Path, description = "The poll id"),
        ("group_id" = IdString, Path, description = "The group id"),
    ),
    responses(
        (status = OK, body = UpdatedPoll, description = "Updated poll"),
        (status = BAD_REQUEST, description = "Invalid poll or group id"),
        (status = NOT_FOUND, description = "Poll not found"),
        (status = CONFLICT, description = "Poll was modified"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
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
        .filter(Database::filter_polls(&claims.sub, vec![], None, false))
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
        (status = BAD_REQUEST, description = "Invalid poll id"),
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
            true,
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
    request_body(content = PublishResults),
    params(
        ("id" = IdString, Path, description = "The poll id"),
    ),
    responses(
        (status = OK, body = UpdatedPoll, description = "Updated poll"),
        (status = BAD_REQUEST, description = "Invalid poll id"),
        (status = NOT_FOUND, description = "Poll not found"),
        (status = CONFLICT, description = "Poll was modified"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
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
            true,
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
    get,
    path = "/api/scheduled-polls",
    description = "Fetch a number of scheduled polls",
    tag = "scheduled polls",
    params(
        ("page" = Option<u64>, Query, minimum = 0),
        ("page_size"  = Option<u64>, Query, minimum = 1, maximum = 10),
        ("asc" = Option<bool>, Query),
        ("sort_by" = Option<FetchScheduledPollSort>, Query)
    ),
    responses(
        (status = OK, body = FetchScheduledPolls, description = "The requested scheduled polls"),
        (status = BAD_REQUEST, description = "Bag paginator options provided"),
    ),
    security(("ac-base" = [])),
)]
async fn _fetch_scheduled_polls() {}

#[utoipa::path(
    get,
    path = "/api/scheduled-polls/{group_id}",
    description = "Fetch a number of scheduled polls",
    tag = "scheduled polls",
    params(
        ("group_id" = IdString, Path, description = "Group id to filter by"),
        ("page" = Option<u64>, Query, minimum = 0),
        ("page_size"  = Option<u64>, Query, minimum = 1, maximum = 10),
        ("asc" = Option<bool>, Query),
        ("sort_by" = Option<FetchScheduledPollSort>, Query)
    ),
    responses(
        (status = OK, body = FetchScheduledPolls, description = "The requested scheduled polls"),
        (status = BAD_REQUEST, description = "Bag paginator options provided"),
    ),
    security(("ac-base" = [])),
)]
async fn fetch_scheduled_polls(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Query(paginator): Query<Paginator<FetchScheduledPollSort>>,
    group_id: Option<axum::extract::Path<IdString>>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    validate_paginator(&paginator, 10)?;

    let pager = sea_entity::scheduled_poll::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(
                    sea_orm::Condition::any()
                        .add(sea_entity::scheduled_poll::Column::OwnerId.eq(claims.sub))
                        .add(sea_entity::scheduled_poll::Column::GroupId.is_in(claims.groups)),
                )
                .add_option(
                    group_id.map(|id| sea_entity::scheduled_poll::Column::GroupId.eq(id.0.0)),
                ),
        )
        .order_by(
            match paginator.sort_by {
                None | Some(FetchScheduledPollSort::NextOccurrence) => {
                    sea_entity::scheduled_poll::Column::NextOccurrence
                }
                Some(FetchScheduledPollSort::CreatedAt) => {
                    sea_entity::scheduled_poll::Column::CreatedAt
                }
            },
            if paginator.asc {
                sea_orm::Order::Asc
            } else {
                sea_orm::Order::Desc
            },
        )
        .paginate(&store.db.sea, paginator.page_size);

    let mut scheduled_polls = Vec::new();

    for scheduled_poll in pager.fetch_page(paginator.page).await? {
        let polls = sea_entity::poll::Entity::find()
            .filter(sea_entity::poll::Column::ScheduledPollId.eq(&scheduled_poll.id))
            .order_by(sea_entity::poll::Column::CreatedAt, sea_orm::Order::Desc)
            .all(&store.db.sea)
            .await?;

        scheduled_polls.push(FetchScheduledPoll {
            id: scheduled_poll.id,
            name: scheduled_poll.name,
            polls: polls.into_iter().map(|m| m.id).collect(),
            updated_at: scheduled_poll.updated_at,
        });
    }

    Ok(Json(FetchScheduledPolls {
        polls: scheduled_polls,
        page: paginator.page,
        page_count: pager.num_items().await?,
    }))
}

#[utoipa::path(
    post,
    path = "/api/scheduled-poll",
    description = "Add a scheduled poll",
    tag = "scheduled polls",
    request_body(content = AddScheduledPoll),
    responses(
        (status = OK, body = FetchScheduledPoll, description = "Scheduled poll created"),
        (status = BAD_REQUEST, description = "Bad options provided"),
        (status = FORBIDDEN, description = "User missing permissions"),
        (status = NOT_FOUND, description = "Group not found"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
    ),
    security(("ac-manage-polls" = [], "ac-manage-scheduled-polls" = [])),
)]
async fn add_scheduled_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(add_poll): Json<AddScheduledPoll>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(
        store,
        auth,
        Permissions::ManagePolls,
        Permissions::ManageScheduledPolls
    )?;
    let now = now().as_secs_f64();

    if now > add_poll.first_occurrence {
        return Err(RestError::bad_req("First occurrence must be in the future"));
    }

    if add_poll.id.is_some() {
        claims.validate(&[Permissions::Admin])?;
    }

    if add_poll.voting_limit == 0 {
        return Err(RestError::bad_req("Voting limit must be greater than 0"));
    }

    if let Some(group) = &add_poll.group
        && !claims.groups.contains(group)
    {
        return Err(RestError::not_found("Group not found"));
    }

    validate_text(&add_poll.name, false, MAX_NAME_LEN)?;
    validate_text(&add_poll.title_template, false, MAX_TITLE_LEN)?;
    validate_text(&add_poll.info, true, MAX_INFO_LEN)?;

    // todo this needs validation for first_occurrence, cutoff, voting_duration and probably the rec rule too
    // they can be to big
    // for edit_poll too

    let scheduled_poll = transaction!(&store.db.sea, txn, {
        let scheduled_poll = sea_entity::scheduled_poll::ActiveModel {
            id: Set(if let Some(id) = add_poll.id {
                id.0
            } else {
                cuid2::create_id()
            }),
            name: Set(add_poll.name),
            cutoff: Set(add_poll.cutoff),
            next_occurrence: Set(add_poll.first_occurrence),
            recurrence_rule: Set(add_poll.recurrence_rule),
            submission_limit: Set(add_poll
                .submission_limit
                .map(|n| {
                    n.try_into()
                        .map_err(|_| RestError::bad_req("Bad submission limit"))
                })
                .transpose()?),
            needs_approval: Set(add_poll.needs_approval),
            reject_duplicates: Set(add_poll.reject_duplicates),
            title_template: Set(add_poll.title_template),
            info: Set(add_poll.info),
            voting_limit: Set(add_poll
                .voting_limit
                .try_into()
                .map_err(|_| RestError::bad_req("Invalid voting limit"))?),
            voting_duration: Set(add_poll.voting_duration),
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

        Ok(scheduled_poll)
    })?;

    Scheduler::run_scheduled_poll_at(
        store.clone(),
        scheduled_poll.id.clone(),
        add_poll.first_occurrence,
        scheduled_poll.updated_at,
        false,
    );

    Ok(Json(FetchScheduledPoll {
        id: scheduled_poll.id,
        name: scheduled_poll.name,
        polls: vec![],
        updated_at: scheduled_poll.updated_at,
    }))
}

#[utoipa::path(
    get,
    path = "/api/scheduled-poll/{id}",
    description = "Fetch a scheduled poll",
    tag = "scheduled polls",
    params(
        ("id" = IdString, Path, description = "The scheduled poll id")
    ),
    responses(
        (status = OK, body = FetchScheduledPoll, description = "The requested scheduled poll"),
        (status = BAD_REQUEST, description = "Invalid scheduled poll id"),
        (status = NOT_FOUND, description = "Scheduled poll not found"),
    ),
    security(("ac-base" = [])),
)]
async fn fetch_scheduled_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let Some(scheduled_poll) = sea_entity::scheduled_poll::Entity::find_by_id(&id.0)
        .filter(
            sea_orm::Condition::any()
                .add(sea_entity::scheduled_poll::Column::OwnerId.eq(claims.sub))
                .add(sea_entity::scheduled_poll::Column::GroupId.is_in(claims.groups)),
        )
        .one(&store.db.sea)
        .await?
    else {
        return Err(RestError::not_found("Scheduled poll not found"));
    };

    let polls = sea_entity::poll::Entity::find()
        .filter(sea_entity::poll::Column::ScheduledPollId.eq(&scheduled_poll.id))
        .order_by(sea_entity::poll::Column::CreatedAt, sea_orm::Order::Desc)
        .all(&store.db.sea)
        .await?;

    Ok(Json(FetchScheduledPoll {
        id: scheduled_poll.id,
        name: scheduled_poll.name,
        polls: polls.into_iter().map(|m| m.id).collect(),
        updated_at: scheduled_poll.updated_at,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/scheduled-poll/{id}",
    description = "Edit a scheduled poll",
    tag = "scheduled polls",
    request_body(content = EditScheduledPoll, description = "The fields to change"),
    params(
        ("id" = IdString, Path, description = "The scheduled poll id")
    ),
    responses(
        (status = OK, body = FetchScheduledPoll, description = "The updated scheduled poll"),
        (status = BAD_REQUEST, description = "Bad options provided"),
        (status = NOT_FOUND, description = "Scheduled poll not found"),
        (status = CONFLICT, description = "Scheduled poll was modified"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
    ),
    security(("ac-manage-polls" = [], "ac-manage-scheduled-polls" = [])),
)]
async fn edit_scheduled_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
    Json(edit_poll): Json<EditScheduledPoll>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(
        store,
        auth,
        Permissions::ManagePolls,
        Permissions::ManageScheduledPolls
    )?;
    let now = now().as_secs_f64();

    let scheduled_poll = sea_entity::scheduled_poll::Entity::find_by_id(&id.0)
        .filter(
            sea_orm::Condition::any()
                .add(sea_entity::scheduled_poll::Column::OwnerId.eq(claims.sub))
                .add(sea_entity::scheduled_poll::Column::GroupId.is_in(claims.groups)),
        )
        .one(&store.db.sea)
        .await?;

    let Some(scheduled_poll) = scheduled_poll else {
        return Err(RestError::not_found("Scheduled Poll not found"));
    };

    // todo it would be good to allow a scheduled poll to be stopped
    if let Some(next_occurrence) = edit_poll.next_occurrence
        && now > next_occurrence
    {
        return Err(RestError::bad_req("Next occurrence must be in the future"));
    };

    let scheduled_poll = transaction!(&store.db.sea, txn, {
        let mut scheduled_poll = scheduled_poll.into_active_model();

        scheduled_poll.name.reset();

        if let Some(name) = edit_poll.name {
            validate_text(&name, false, MAX_NAME_LEN)?;
            scheduled_poll.name = Set(name);
        }

        if let Some(next_occurrence) = edit_poll.next_occurrence {
            scheduled_poll.next_occurrence = Set(next_occurrence)
        }

        if let Some(cutoff) = edit_poll.cutoff {
            scheduled_poll.cutoff = Set(cutoff);
        }

        if let Some(recurrence_rule) = edit_poll.recurrence_rule {
            scheduled_poll.recurrence_rule = Set(recurrence_rule);
        }

        if let Some(submission_limit) = edit_poll.submission_limit {
            scheduled_poll.submission_limit = Set(submission_limit
                .map(|n| {
                    n.try_into()
                        .map_err(|_| RestError::bad_req("Bad submission limit"))
                })
                .transpose()?);
        }

        if let Some(needs_approval) = edit_poll.needs_approval {
            scheduled_poll.needs_approval = Set(needs_approval);
        }

        if let Some(reject_duplicates) = edit_poll.reject_duplicates {
            scheduled_poll.reject_duplicates = Set(reject_duplicates);
        }

        if let Some(title_template) = edit_poll.title_template {
            validate_text(&title_template, false, MAX_TITLE_LEN)?;
            scheduled_poll.title_template = Set(title_template);
        }

        if let Some(info) = edit_poll.info {
            validate_text(&info, true, MAX_INFO_LEN)?;
            scheduled_poll.info = Set(info);
        }

        if let Some(voting_limit) = edit_poll.voting_limit {
            scheduled_poll.voting_limit = Set(voting_limit
                .try_into()
                .map_err(|_| RestError::bad_req("Bad voting limit"))?);
        }

        if let Some(voting_duration) = edit_poll.voting_duration {
            scheduled_poll.voting_duration = Set(voting_duration);
        }

        let scheduled_polls = sea_entity::scheduled_poll::Entity::update_many()
            .set(scheduled_poll)
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::scheduled_poll::Column::Id.eq(id.0))
                    .add(sea_entity::scheduled_poll::Column::UpdatedAt.eq(edit_poll.updated_at)),
            )
            .exec_with_returning(txn)
            .await?;

        if scheduled_polls.len() != 1 {
            return Err(RestError::conflict("Scheduled poll was modified"));
        }

        let scheduled_poll = scheduled_polls.into_iter().next().unwrap();

        Ok(scheduled_poll)
    })?;

    Scheduler::run_scheduled_poll_at(
        store.clone(),
        scheduled_poll.id.clone(),
        scheduled_poll.next_occurrence,
        scheduled_poll.updated_at,
        false,
    );

    let polls = sea_entity::poll::Entity::find()
        .filter(sea_entity::poll::Column::ScheduledPollId.eq(&scheduled_poll.id))
        .order_by(sea_entity::poll::Column::CreatedAt, sea_orm::Order::Desc)
        .all(&store.db.sea)
        .await?;

    Ok(Json(FetchScheduledPoll {
        id: scheduled_poll.id,
        name: scheduled_poll.name,
        polls: polls.into_iter().map(|m| m.id).collect(),
        updated_at: scheduled_poll.updated_at,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/scheduled-poll/{id}",
    description = "Remove a scheduled poll",
    tag = "scheduled polls",
    params(
        ("id" = IdString, Path, description = "The scheduled poll id")
    ),
    responses(
        (status = OK, description = "Scheduled poll deleted"),
        (status = BAD_REQUEST, description = "Invalid scheduled poll id"),
        (status = NOT_FOUND, description = "Scheduled poll not found"),
    ),
    security(("ac-manage-polls" = [], "ac-manage-scheduled-polls" = [])),
)]
async fn remove_scheduled_poll(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(
        store,
        auth,
        Permissions::ManagePolls,
        Permissions::ManageScheduledPolls
    )?;

    let scheduled_poll = sea_entity::scheduled_poll::Entity::find_by_id(&id.0)
        .filter(
            sea_orm::Condition::any()
                .add(sea_entity::scheduled_poll::Column::OwnerId.eq(claims.sub))
                .add(sea_entity::scheduled_poll::Column::GroupId.is_in(claims.groups)),
        )
        .one(&store.db.sea)
        .await?;

    let Some(scheduled_poll) = scheduled_poll else {
        return Err(RestError::not_found("Scheduled Poll not found"));
    };

    let images = transaction!(&store.db.sea, txn, {
        let polls = sea_entity::poll::Entity::find()
            .filter(sea_entity::poll::Column::ScheduledPollId.eq(&scheduled_poll.id))
            .all(txn)
            .await?;

        let mut images = Vec::new();

        for poll in polls {
            images.extend(
                sea_entity::image::Entity::delete_many()
                    .filter(sea_entity::image::Column::PollId.eq(&poll.id))
                    .exec_with_returning(txn)
                    .await?
                    .into_iter()
                    .map(|image| image.id),
            );

            poll.into_active_model().delete(txn).await?;
        }

        let scheduled_images = sea_entity::scheduled_image::Entity::delete_many()
            .filter(sea_entity::scheduled_image::Column::ScheduledPollId.eq(&scheduled_poll.id))
            .exec_with_returning(txn)
            .await?
            .into_iter()
            .map(|image| image.image_id)
            .collect::<Vec<_>>();

        images.extend(
            sea_entity::image::Entity::delete_many()
                .filter(sea_entity::image::Column::Id.is_in(scheduled_images))
                .exec_with_returning(txn)
                .await?
                .into_iter()
                .map(|image| image.id),
        );

        scheduled_poll.into_active_model().delete(txn).await?;

        Ok(images)
    })?;

    for image in images {
        let path = store.image_path.join(&image);
        remove_file(&path, &image).await;
    }

    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/scheduled-poll/{id}/submissions",
    description = "Fetch the current submissions to a scheduled poll",
    tag = "scheduled polls",
    params(
        ("id" = IdString, Path, description = "The scheduled poll id"),
    ),
    responses(
        (status = OK, body = FetchScheduledPollSubmissions, description = "The submissions to the scheduled poll"),
        (status = BAD_REQUEST, description = "Invalid scheduled poll id"),
        (status = NOT_FOUND, description = "Scheduled poll not found"),
    )
)]
pub async fn fetch_scheduled_poll_submissions(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let Some(scheduled_poll) = sea_entity::scheduled_poll::Entity::find_by_id(&id.0)
        .filter(
            sea_orm::Condition::any()
                .add(sea_entity::scheduled_poll::Column::OwnerId.eq(claims.sub))
                .add(sea_entity::scheduled_poll::Column::GroupId.is_in(claims.groups)),
        )
        .one(&store.db.sea)
        .await?
    else {
        return Err(RestError::not_found("Scheduled poll not found"));
    };

    let images = sea_entity::scheduled_image::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::scheduled_image::Column::ScheduledPollId.eq(&scheduled_poll.id))
                .add(
                    sea_entity::scheduled_image::Column::NextOccurrence
                        .eq(scheduled_poll.next_occurrence),
                ),
        )
        .find_also_related(sea_entity::image::Entity)
        .all(&store.db.sea)
        .await?;

    let mut submissions = Vec::new();

    for image in images {
        let (scheduled_image, Some(image)) = image else {
            return Err(RestError::internal(
                "Scheduled image has no associated image",
            ));
        };

        let Some(owner_id) = image.owner_id else {
            return Err(RestError::internal("Submitted image has no owner"));
        };

        submissions.push(ScheduledPollSubmission {
            image_id: scheduled_image.image_id,
            user_id: owner_id,
            approved: scheduled_image.approved,
            submitted_at: scheduled_image.created_at,
        });
    }

    Ok(Json(FetchScheduledPollSubmissions { submissions }))
}

#[utoipa::path(
    patch,
    path = "/api/scheduled-poll/{id}/approve",
    description = "Approve a submission to a scheduled poll",
    tag = "scheduled polls",
    request_body(content = ApproveScheduledPollSubmission),
    params(
        ("id" = IdString, Path, description = "The scheduled poll id"),
    ),
    responses(
        (status = OK, description = "Submission approval updated"),
        (status = BAD_REQUEST, description = "Submission not found"),
        (status = NOT_FOUND, description = "Scheduled poll not found"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
    )
)]
pub async fn approve_scheduled_poll_submission(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
    Json(approve_submission): Json<ApproveScheduledPollSubmission>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ApproveScheduledPollSubmissions)?;

    let Some(scheduled_poll) = sea_entity::scheduled_poll::Entity::find_by_id(&id.0)
        .filter(
            sea_orm::Condition::any()
                .add(sea_entity::scheduled_poll::Column::OwnerId.eq(claims.sub))
                .add(sea_entity::scheduled_poll::Column::GroupId.is_in(claims.groups)),
        )
        .one(&store.db.sea)
        .await?
    else {
        return Err(RestError::not_found("Scheduled poll not found"));
    };

    let Some(scheduled_image) = sea_entity::scheduled_image::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::scheduled_image::Column::ImageId.eq(&approve_submission.image_id))
                .add(sea_entity::scheduled_image::Column::ScheduledPollId.eq(&id.0))
                .add(
                    sea_entity::scheduled_image::Column::NextOccurrence
                        .eq(scheduled_poll.next_occurrence),
                ),
        )
        .one(&store.db.sea)
        .await?
    else {
        return Err(RestError::bad_req("Submission not found"));
    };

    let updated = transaction!(&store.db.sea, txn, {
        let mut scheduled_image = scheduled_image.into_active_model();
        scheduled_image.approved = Set(approve_submission.approved);
        scheduled_image.update(txn).await?;

        if approve_submission.approved {
            let mut scheduled_poll = scheduled_poll.into_active_model();
            scheduled_poll.updated_at.reset();
            let scheduled_poll = scheduled_poll.update(txn).await?;
            Ok(Some((
                scheduled_poll.next_occurrence,
                scheduled_poll.updated_at,
            )))
        } else {
            Ok(None)
        }
    })?;

    if let Some((next_occurrence, updated_at)) = updated {
        Scheduler::run_scheduled_poll_at(store.clone(), id.0, next_occurrence, updated_at, false);
    }

    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/scheduled-poll/{id}/submit",
    description = "Fetch your submission to a scheduled poll",
    tag = "scheduled polls",
    params(
        ("id" = IdString, Path, description = "The scheduled poll id"),
    ),
    responses(
        (status = OK, body = FetchScheduledPollSubmission, description = "The submission"),
        (status = BAD_REQUEST, description = "Invalid scheduled poll id"),
        (status = NOT_FOUND, description = "Scheduled poll not found"),
    ),
    security(("ac-base" = [])),
)]
async fn fetch_scheduled_poll_submission(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;

    let Some(scheduled_poll) = sea_entity::scheduled_poll::Entity::find_by_id(&id.0)
        .one(&store.db.sea)
        .await?
    else {
        return Err(RestError::not_found("Scheduled poll not found"));
    };

    let images = sea_entity::image::Entity::find()
        .join(
            JoinType::InnerJoin,
            sea_entity::image::Relation::ScheduledImage.def(),
        )
        .filter(
            sea_orm::Condition::all()
                .add(sea_entity::image::Column::OwnerId.eq(&claims.sub))
                .add(sea_entity::scheduled_image::Column::ScheduledPollId.eq(&scheduled_poll.id))
                .add(
                    sea_entity::scheduled_image::Column::NextOccurrence
                        .eq(scheduled_poll.next_occurrence),
                ),
        )
        .select_only()
        .columns(sea_entity::image::Column::iter())
        .into_model::<sea_entity::image::Model>()
        .all(&store.db.sea)
        .await?
        .into_iter()
        .map(|m| m.id)
        .collect();

    Ok(Json(FetchScheduledPollSubmission { images }))
}

#[utoipa::path(
    patch,
    path = "/api/scheduled-poll/{id}/submit",
    description = "Edit your submission to a scheduled poll",
    tag = "scheduled polls",
    request_body(content = EditScheduledPollSubmission, description = "The updates to the submission"),
    params(
        ("id" = IdString, Path, description = "The scheduled poll id"),
    ),
    responses(
        (status = OK, body = FetchScheduledPollSubmission, description = "Submission updated"),
        (status = BAD_REQUEST, description = "Bad options provided"),
        (status = NOT_FOUND, description = "Scheduled poll not found"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
    ),
    security(("ac-base" = [])),
)]
async fn edit_scheduled_poll_submission(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    axum::extract::Path(id): axum::extract::Path<IdString>,
    Json(submission): Json<EditScheduledPollSubmission>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth)?;
    let now = now().as_secs_f64();

    let Some(scheduled_poll) = sea_entity::scheduled_poll::Entity::find_by_id(&id.0)
        .one(&store.db.sea)
        .await?
    else {
        return Err(RestError::not_found("Scheduled poll not found"));
    };

    let next_occurrence = find_next_run(
        now,
        scheduled_poll.next_occurrence,
        scheduled_poll.cutoff,
        &scheduled_poll.recurrence_rule,
    )?;

    async fn has_not_previously_been_submitted<C>(
        scheduled_poll_id: &str,
        hash: &str,
        db: &C,
    ) -> Result<bool, RestError>
    where
        C: ConnectionTrait,
    {
        Ok(sea_entity::image::Entity::find()
            .join(JoinType::InnerJoin, sea_entity::image::Relation::Poll.def())
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::poll::Column::ScheduledPollId.eq(scheduled_poll_id))
                    .add(sea_entity::image::Column::Hash.eq(hash)),
            )
            .select_only()
            .columns(sea_entity::image::Column::iter())
            .into_model::<sea_entity::image::Model>()
            .all(db)
            .await?
            .is_empty()
            && sea_entity::scheduled_image::Entity::find()
                .join(
                    JoinType::InnerJoin,
                    sea_entity::scheduled_image::Relation::Image.def(),
                )
                .filter(
                    sea_orm::Condition::all()
                        .add(
                            sea_entity::scheduled_image::Column::ScheduledPollId
                                .eq(scheduled_poll_id),
                        )
                        .add(sea_entity::image::Column::Hash.eq(hash)),
                )
                .select_only()
                .columns(sea_entity::image::Column::iter())
                .into_model::<sea_entity::image::Model>()
                .all(db)
                .await?
                .is_empty())
    }

    transaction!(&store.db.sea, txn, {
        let add_images = sea_entity::image::Entity::find()
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::image::Column::Id.is_in(submission.add_images.clone()))
                    .add(sea_entity::image::Column::OwnerId.eq(&claims.sub))
                    .add(sea_entity::image::Column::PollId.is_null())
                    .add(
                        sea_entity::image::Column::Id.not_in_subquery(
                            sea_query::Query::select()
                                .from(sea_entity::scheduled_image::Entity)
                                .column(sea_entity::scheduled_image::Column::ImageId)
                                .to_owned(),
                        ),
                    ),
            )
            .all(txn)
            .await?;

        if add_images.len() != submission.add_images.len() {
            return Err(RestError::bad_req("Invalid images"));
        }

        for image in add_images {
            if scheduled_poll.reject_duplicates
                && !has_not_previously_been_submitted(&id.0, &image.hash, txn).await?
            {
                return Err(RestError::conflict("Image has been submitted before"));
            }

            sea_entity::scheduled_image::ActiveModel {
                image_id: Set(image.id),
                scheduled_poll_id: Set(scheduled_poll.id.clone()),
                next_occurrence: Set(next_occurrence),
                approved: Set(false),
                ..Default::default()
            }
            .insert(txn)
            .await?;
        }

        let remove_images = sea_entity::scheduled_image::Entity::delete_many()
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::scheduled_image::Column::ScheduledPollId.eq(&id.0))
                    .add(
                        sea_entity::scheduled_image::Column::ImageId
                            .is_in(&submission.remove_images),
                    ),
            )
            .exec(txn)
            .await?;

        if remove_images.rows_affected != submission.remove_images.len() as u64 {
            return Err(RestError::bad_req("Invalid remove images"));
        }

        let submitted = sea_entity::scheduled_image::Entity::find()
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::scheduled_image::Column::ScheduledPollId.eq(&id.0))
                    .add(sea_entity::scheduled_image::Column::NextOccurrence.eq(next_occurrence)),
            )
            .all(txn)
            .await?;

        if let Some(submission_limit) = scheduled_poll.submission_limit
            && submitted.len() > submission_limit as usize
        {
            return Err(RestError::bad_req("Submission limit exceeded"));
        }

        Ok(Json(FetchScheduledPollSubmission {
            images: submitted.into_iter().map(|img| img.image_id).collect(),
        }))
    })
}
