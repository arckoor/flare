use std::sync::Arc;

use axum::{Json, Router, extract::State, response::IntoResponse, routing};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use sea_entity::sea_orm_active_enums::Permissions;
use sea_orm::{IntoActiveModel, Set, TransactionTrait, entity::prelude::*};

use crate::{
    api::{
        api_params::{AddGroup, EditGroup, FetchGroup, IdString, Member},
        error::RestError,
        services::remove_file,
        validation::{MAX_NAME_LEN, validate_text},
    },
    db::Database,
    store::Store,
};
use crate::{requires, transaction};

pub fn build_router() -> Router<Arc<Store>> {
    Router::new()
        .route("/group/{id}", routing::post(join_group))
        .route("/group/{id}", routing::delete(leave_group))
        .route("/groups", routing::post(add_group))
        .route("/groups/{id}", routing::get(fetch_group))
        .route("/groups/{id}", routing::patch(edit_group))
        .route("/groups/{id}", routing::delete(remove_group))
        .route("/groups/{id}/{user_id}", routing::post(add_group_user))
        .route("/groups/{id}/{user_id}", routing::delete(remove_group_user))
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
        (status = BAD_REQUEST, description = "Invalid group id"),
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
        (status = BAD_REQUEST, description = "Invalid group id"),
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
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
    ),
    security(("ac-manage-groups" = [])),
)]
async fn add_group(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(add_group): Json<AddGroup>,
) -> Result<impl IntoResponse, RestError> {
    let claims = requires!(store, auth, Permissions::ManageGroups)?;

    validate_text(&add_group.name, false, MAX_NAME_LEN)?;

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
        (status = BAD_REQUEST, description = "Invalid group id"),
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
    request_body(content = EditGroup, description = "The fields to change"),
    params(
        ("id" = IdString, Path, description = "Group id")
    ),
    responses(
        (status = OK, body = FetchGroup, description = "The updated group"),
        (status = BAD_REQUEST, description = "Invalid group id"),
        (status = FORBIDDEN, description = "New owner is missing permissions"),
        (status = NOT_FOUND, description = "Group not found"),
        (status = CONFLICT, description = "Group was modified"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
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
            validate_text(&name, false, MAX_NAME_LEN)?;
            group.name = Set(name);
        }

        if let Some(owner_id) = edit_group.owner
            && owner_id.0 != claims.sub
        {
            let group_user =
                sea_entity::group_user::Entity::find_by_id((id.0.clone(), owner_id.0.clone()))
                    .find_also_related(sea_entity::user::Entity)
                    .one(txn)
                    .await?;

            let Some((_, Some(new_owner))) = group_user else {
                return Err(RestError::bad_req("User not found"));
            };

            if !new_owner.permissions.contains(&Permissions::ManageGroups) {
                return Err(RestError::forbidden("User cannot manage groups"));
            }

            group.owner_id = Set(owner_id.0);
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
        (status = BAD_REQUEST, description = "Invalid group id"),
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
        // todo also scheduled polls

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
        (status = BAD_REQUEST, description = "User not found or already in group"),
        (status = NOT_FOUND, description = "Group not found"),
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
        return Err(RestError::bad_req("User not found"));
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

    // todo would be nice to also be able to un-invite a user here

    if sea_entity::group_user::Entity::find_by_id((id.0.clone(), user_id.0.clone()))
        .one(&store.db.sea)
        .await?
        .is_none()
    {
        return Err(RestError::bad_req("User not in group"));
    }

    let inner_user_id = user_id.0.clone();
    transaction!(&store.db.sea, txn, {
        Database::remove_user_from_group(txn, &id.0, &inner_user_id).await
    })?;

    store.jwt.revoke_access(&user_id.0).await?;

    Ok(())
}
