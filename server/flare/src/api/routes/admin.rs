use std::sync::Arc;

use axum::{Json, Router, extract::State, response::IntoResponse, routing};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use hyper::StatusCode;
use sea_entity::sea_orm_active_enums::Permissions;
use sea_orm::EntityTrait;

use crate::{
    api::{api_params::Task, error::RestError},
    requires,
    store::Store,
    tasks::Tasks,
};

pub fn build_router() -> Router<Arc<Store>> {
    Router::new().route("/admin/run", routing::post(run_task))
}

#[utoipa::path(
    post,
    path = "/api/admin/run",
    description = "Run a task",
    tag = "admin",
    request_body(content = Task, description = "The task to run"),
    responses(
        (status = ACCEPTED, description = "Task scheduled"),
        (status = BAD_REQUEST, description = "Bad options provided"),
        (status = NOT_FOUND, description = "Scheduled poll not found"),
        (status = UNPROCESSABLE_ENTITY, description = "Body is invalid JSON"),
    ),
    security(("ac-admin" = []))
)]
async fn run_task(
    State(store): State<Arc<Store>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(task): Json<Task>,
) -> Result<impl IntoResponse, RestError> {
    requires!(store, auth, Permissions::Admin)?;

    match task {
        Task::CleanOldInvites => {
            tokio::spawn(async move {
                Tasks::clean_old_images(store.db.clone(), store.image_path.clone()).await
            });
        }
        Task::CleanOldImages => {
            tokio::spawn(async move {
                Tasks::clean_old_images(store.db.clone(), store.image_path.clone()).await
            });
        }
        Task::LockOldPolls => {
            tokio::spawn(async move { Tasks::lock_old_polls(store.db.clone()).await });
        }
        Task::RunScheduledPoll(id) => {
            let Some(scheduled_poll) = sea_entity::scheduled_poll::Entity::find_by_id(id.0)
                .one(&store.db.sea)
                .await?
            else {
                return Err(RestError::not_found("Scheduled poll not found"));
            };

            tokio::spawn(async move {
                Tasks::run_scheduled_poll(
                    store.clone(),
                    scheduled_poll.id,
                    scheduled_poll.updated_at,
                    true,
                )
                .await
            });
        }
    }

    Ok(StatusCode::ACCEPTED)
}
