use std::path::PathBuf;
use std::pin::Pin;
use std::{sync::Arc, time::Duration};

use sea_orm::ActiveValue::Set;
use sea_orm::{IntoActiveModel, JoinType, QuerySelect, sea_query};
use sea_orm::{Iterable, TransactionTrait, entity::prelude::*};
use tokio::time::{self, sleep};
use tracing::{instrument, warn};

use crate::api::error::RestError;
use crate::db::Database;
use crate::store::Store;
use crate::time::{ONE_WEEK, minutes, next_run, now};
use crate::transaction;

pub struct Scheduler;

impl Scheduler {
    pub async fn schedule_all(store: Arc<Store>) {
        #[allow(clippy::type_complexity)]
        let tasks: Vec<(
            Duration,
            Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>,
        )> = vec![
            (
                minutes(5),
                Box::new({
                    let db = store.db.clone();
                    move || Box::pin(Tasks::clean_old_invites(db.clone()))
                }),
            ),
            (
                minutes(30),
                Box::new({
                    let db = store.db.clone();
                    let path = store.image_path.clone();
                    move || Box::pin(Tasks::clean_old_images(db.clone(), path.clone()))
                }),
            ),
            (
                minutes(5),
                Box::new({
                    let db = store.db.clone();
                    move || Box::pin(Tasks::lock_old_polls(db.clone()))
                }),
            ),
        ];

        for (interval, task) in tasks.into_iter() {
            tokio::spawn(async move {
                let mut interval = time::interval_at(time::Instant::now() + interval, interval);
                interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
                loop {
                    task().await;
                    interval.tick().await;
                }
            });
        }

        let scheduled_polls = sea_entity::scheduled_poll::Entity::find()
            .all(&store.db.sea)
            .await
            .expect("Failed to query scheduled polls");

        for scheduled in scheduled_polls {
            Self::run_scheduled_poll_at(
                store.clone(),
                scheduled.id,
                scheduled.next_occurrence,
                scheduled.updated_at,
                false,
            );
        }
    }

    pub fn run_scheduled_poll_at(
        store: Arc<Store>,
        scheduled_id: String,
        next_occurrence: f64,
        updated_at: f64,
        oneshot: bool,
    ) {
        tokio::spawn(async move {
            let now = now().as_secs_f64();
            let delay = (next_occurrence - now).max(0.0) + 10.0; // a bit of grace time
            sleep(Duration::from_secs_f64(delay)).await;
            Tasks::run_scheduled_poll(store, scheduled_id, updated_at, oneshot).await;
        });
    }

    pub fn run_scheduled_poll_in(
        store: Arc<Store>,
        scheduled_id: String,
        delay: f64,
        updated_at: f64,
        oneshot: bool,
    ) {
        warn!(
            "Scheduled poll {} was rescheduled because of an error",
            scheduled_id
        );
        tokio::spawn(async move {
            sleep(Duration::from_secs_f64(delay)).await;
            Tasks::run_scheduled_poll(store, scheduled_id, updated_at, oneshot).await;
        });
    }
}

pub struct Tasks;

impl Tasks {
    #[instrument(skip_all)]
    pub async fn clean_old_invites(db: Arc<Database>) {
        let now = now().as_secs_f64();

        let _ = sea_entity::group_join_request::Entity::delete_many()
            .filter(sea_entity::group_join_request::Column::CreatedAt.lt(now - ONE_WEEK))
            .exec_with_returning(&db.sea)
            .await
            .map_err(RestError::from);
    }

    #[instrument(skip_all)]
    pub async fn clean_old_images(db: Arc<Database>, image_path: PathBuf) {
        let now = now().as_secs_f64();

        let deleted_images = sea_entity::image::Entity::delete_many()
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::image::Column::PollId.is_null())
                    .add(sea_entity::image::Column::CreatedAt.lt(now - ONE_WEEK))
                    .add(
                        sea_entity::image::Column::Id.not_in_subquery(
                            sea_query::Query::select()
                                .from(sea_entity::scheduled_image::Entity)
                                .column(sea_entity::scheduled_image::Column::ImageId)
                                .to_owned(),
                        ),
                    ),
            )
            .exec_with_returning(&db.sea)
            .await
            .map_err(RestError::from)
            .unwrap_or_default()
            .into_iter()
            .map(|model| model.id)
            .collect::<Vec<_>>();

        for image in deleted_images.into_iter() {
            let path = image_path.join(image);
            if path.exists() {
                let _ = tokio::fs::remove_file(path).await.map_err(RestError::from);
            }
        }

        // if we somehow end up with files that don't have a db entry, just delete them
        if let Ok(mut read_dir) = tokio::fs::read_dir(image_path).await {
            while let Ok(Some(file)) = read_dir.next_entry().await {
                if let Ok(name) = file.file_name().into_string()
                    && let Ok(None) = sea_entity::image::Entity::find_by_id(&name)
                        .one(&db.sea)
                        .await
                        .map_err(RestError::from)
                {
                    let _ = tokio::fs::remove_file(file.path())
                        .await
                        .map_err(RestError::from);
                }
            }
        }
    }

    #[instrument(skip_all)]
    pub async fn lock_old_polls(db: Arc<Database>) {
        let now = now().as_secs_f64();

        let polls = sea_entity::poll::Entity::find()
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::poll::Column::Locked.eq(false))
                    .add(sea_entity::poll::Column::Ends.lt(now - ONE_WEEK * 2.0)),
            )
            .all(&db.sea)
            .await
            .map_err(RestError::from)
            .unwrap_or_default();

        for poll in polls {
            let _ = transaction!(&db.sea, txn, {
                let updated = sea_entity::poll::Entity::update_many()
                    .col_expr(sea_entity::poll::Column::Locked, Expr::value(true))
                    .filter(
                        sea_orm::Condition::all()
                            .add(sea_entity::poll::Column::Id.eq(&poll.id))
                            .add(sea_entity::poll::Column::UpdatedAt.eq(poll.updated_at)),
                    )
                    .exec_with_returning(txn)
                    .await?;

                if updated.len() != 1 {
                    return Err(RestError::conflict("Poll was modified during locking"));
                }

                let votes = sea_entity::vote::Entity::find()
                    .join(JoinType::InnerJoin, sea_entity::vote::Relation::Image.def())
                    .filter(sea_entity::image::Column::PollId.eq(&poll.id))
                    .select_only()
                    .columns(sea_entity::vote::Column::iter())
                    .into_model::<sea_entity::vote::Model>()
                    .all(txn)
                    .await?
                    .into_iter()
                    .map(|model| model.id);

                sea_entity::ephemeral_user_vote::Entity::delete_many()
                    .filter(sea_entity::ephemeral_user_vote::Column::VoteId.is_in(votes))
                    .exec_with_returning(txn)
                    .await?;

                Ok(())
            });
        }
    }

    #[instrument(skip_all)]
    pub async fn expire_old_ephemeral_users(db: Arc<Database>) {
        let now = now().as_secs_f64();

        let orphaned_users = sea_entity::ephemeral_user::Entity::find()
            .join(
                JoinType::LeftJoin,
                sea_entity::ephemeral_user::Relation::EphemeralUserVote.def(),
            )
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::ephemeral_user::Column::LastSeenAt.lt(now - ONE_WEEK))
                    .add(sea_entity::ephemeral_user_vote::Column::EphemeralUserId.is_null()),
            )
            .all(&db.sea)
            .await
            .map_err(RestError::from)
            .unwrap_or_default();

        for user in orphaned_users {
            let _ = sea_entity::ephemeral_user::Entity::delete_by_id(user.id)
                .filter(sea_entity::ephemeral_user::Column::LastSeenAt.eq(user.last_seen_at))
                .exec(&db.sea)
                .await
                .map_err(RestError::from);
        }
    }

    #[instrument(skip(store))]
    pub async fn run_scheduled_poll(
        store: Arc<Store>,
        scheduled_id: String,
        updated_at: f64,
        oneshot: bool,
    ) {
        let now = now().as_secs_f64();

        let Ok(maybe_scheduled_poll) =
            sea_entity::scheduled_poll::Entity::find_by_id(&scheduled_id)
                .one(&store.db.sea)
                .await
                .map_err(RestError::from)
        else {
            if !oneshot {
                // reschedule because of error
                Scheduler::run_scheduled_poll_in(store, scheduled_id, 60.0, updated_at, oneshot);
            }
            return;
        };

        let Some(scheduled_poll) = maybe_scheduled_poll else {
            // it doesn't exist anymore
            return;
        };

        if scheduled_poll.updated_at != updated_at {
            // the poll was modified, so another task has been scheduled to take care of it
            return;
        }

        if now < scheduled_poll.next_occurrence {
            if !oneshot {
                // it shouldn't occur yet, reschedule to when it should
                warn!(
                    "Poll {} tried to run at {}, but should run at {}",
                    scheduled_id, now, scheduled_poll.next_occurrence
                );
                Scheduler::run_scheduled_poll_at(
                    store,
                    scheduled_id,
                    scheduled_poll.next_occurrence,
                    scheduled_poll.updated_at,
                    oneshot,
                );
            }
            return;
        }

        let submitted = sea_entity::scheduled_image::Entity::find()
            .filter(
                sea_orm::Condition::all()
                    .add(
                        sea_entity::scheduled_image::Column::ScheduledPollId.eq(&scheduled_poll.id),
                    )
                    .add(
                        sea_entity::scheduled_image::Column::NextOccurrence
                            .eq(scheduled_poll.next_occurrence),
                    ),
            )
            .all(&store.db.sea)
            .await
            .map_err(RestError::from)
            .unwrap_or_default();

        if scheduled_poll.needs_approval && submitted.into_iter().any(|img| !img.approved) {
            // some images still need to be approved, don't reschedule, will happen when all images are approved
            return;
        }

        let Ok(result) = transaction!(&store.db.sea, txn, {
            let submitted = sea_entity::scheduled_image::Entity::delete_many()
                .filter(
                    sea_orm::Condition::all()
                        .add(
                            sea_entity::scheduled_image::Column::ScheduledPollId
                                .eq(&scheduled_poll.id),
                        )
                        .add(
                            sea_entity::scheduled_image::Column::NextOccurrence
                                .eq(scheduled_poll.next_occurrence),
                        ),
                )
                .exec_with_returning(txn)
                .await?
                .into_iter()
                .map(|s| s.image_id)
                .collect::<Vec<_>>();

            if submitted.len() >= 2 {
                let poll = sea_entity::poll::ActiveModel {
                    id: Set(cuid2::slug()),
                    title: Set(scheduled_poll.title_template.clone()), // todo this needs to actually process the template
                    info: Set(scheduled_poll.info.clone()),
                    ends: Set(scheduled_poll.next_occurrence + scheduled_poll.voting_duration),
                    locked: Set(false),
                    results_public: Set(false),
                    voting_limit: Set(scheduled_poll.voting_limit),
                    owner_id: Set(scheduled_poll.owner_id.clone()),
                    group_id: Set(scheduled_poll.group_id.clone()),
                    scheduled_poll_id: Set(if scheduled_poll.recurrence_rule.is_some() {
                        Some(scheduled_poll.id.clone())
                    } else {
                        None
                    }),
                    ..Default::default()
                }
                .insert(txn)
                .await?;

                let res = {
                    let mut stmt = sea_entity::image::Entity::update_many().col_expr(
                        sea_entity::image::Column::PollId,
                        Expr::value(poll.id.clone()),
                    );

                    if let Some(group_id) = scheduled_poll.group_id.clone() {
                        stmt = stmt
                            .col_expr(
                                sea_entity::image::Column::OwnerId,
                                Expr::value(None::<String>),
                            )
                            .col_expr(sea_entity::image::Column::GroupId, Expr::value(group_id));
                    } else {
                        stmt = stmt.col_expr(
                            sea_entity::image::Column::OwnerId,
                            Expr::value(scheduled_poll.owner_id.clone()),
                        )
                    }

                    stmt
                }
                .filter(sea_entity::image::Column::Id.is_in(submitted.clone()))
                .exec(txn)
                .await?;

                if res.rows_affected as usize != submitted.len() {
                    return Err(RestError::conflict(
                        "Some images could not be added to the new poll",
                    ));
                }
            }

            if scheduled_poll.recurrence_rule.is_some() {
                let next_run = next_run(
                    scheduled_poll.next_occurrence,
                    &scheduled_poll.recurrence_rule,
                )?;

                let mut scheduled_poll = scheduled_poll.into_active_model();
                scheduled_poll.next_occurrence = Set(next_run);

                let scheduled_poll = scheduled_poll.update(txn).await?;

                Ok(Some((next_run, scheduled_poll.updated_at)))
            } else {
                scheduled_poll.into_active_model().delete(txn).await?;
                Ok(None)
            }
        }) else {
            if !oneshot {
                Scheduler::run_scheduled_poll_in(store, scheduled_id, 60.0, updated_at, oneshot);
            }
            return;
        };

        if let Some((next_run, updated_at)) = result {
            // we ignore the oneshot setting here, because we modified the poll above, so we're now
            // responsible for the poll continuing to run (since the old task will terminate)
            Scheduler::run_scheduled_poll_at(
                store.clone(),
                scheduled_id,
                next_run,
                updated_at,
                false,
            )
        }
    }
}
