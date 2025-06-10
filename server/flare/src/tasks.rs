use std::path::PathBuf;
use std::pin::Pin;
use std::{sync::Arc, time::Duration};

use sea_orm::{Iterable, TransactionTrait, entity::prelude::*};
use sea_orm::{JoinType, QuerySelect};
use tokio::time;
use tracing::instrument;

use crate::api::error::RestError;
use crate::db::Database;
use crate::time::{ONE_WEEK, minutes, now};
use crate::transaction;

pub struct Scheduler {
    db: Arc<Database>,
    image_path: PathBuf,
}

type Task = Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

impl Scheduler {
    pub async fn new(db: Arc<Database>, image_path: PathBuf) -> Self {
        let tasks = Self { db, image_path };
        tasks.schedule_all().await;
        tasks
    }

    async fn schedule_all(&self) {
        let tasks: Vec<(Duration, Task)> = vec![
            (
                minutes(5),
                Box::new({
                    let db = self.db.clone();
                    move || Box::pin(Tasks::clean_old_invites(db.clone()))
                }),
            ),
            (
                minutes(30),
                Box::new({
                    let db = self.db.clone();
                    let path = self.image_path.clone();
                    move || Box::pin(Tasks::clean_old_images(db.clone(), path.clone()))
                }),
            ),
            (
                minutes(5),
                Box::new({
                    let db = self.db.clone();
                    move || Box::pin(Tasks::lock_old_polls(db.clone()))
                }),
            ),
        ];

        for (interval, task_fn) in tasks.into_iter() {
            self.schedule(interval, task_fn);
            time::sleep(Duration::from_millis(500)).await;
        }
    }

    fn schedule(&self, interval: Duration, task_fn: Task) {
        tokio::spawn(async move {
            let mut interval = time::interval_at(time::Instant::now() + interval, interval);
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            loop {
                task_fn().await;
                interval.tick().await;
            }
        });
    }
}

pub struct Tasks;

impl Tasks {
    #[instrument(skip(db))]
    pub async fn clean_old_invites(db: Arc<Database>) {
        let now = now().as_secs_f64();

        let _ = sea_entity::group_join_request::Entity::delete_many()
            .filter(sea_entity::group_join_request::Column::CreatedAt.lt(now - ONE_WEEK))
            .exec_with_returning(&db.sea)
            .await
            .map_err(RestError::from);
    }

    #[instrument(skip(db, image_path))]
    pub async fn clean_old_images(db: Arc<Database>, image_path: PathBuf) {
        let now = now().as_secs_f64();

        let deleted_images = sea_entity::image::Entity::delete_many()
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::image::Column::PollId.is_null())
                    .add(sea_entity::image::Column::CreatedAt.lt(now - ONE_WEEK)),
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
                if let Ok(name) = file.file_name().into_string() {
                    if let Ok(None) = sea_entity::image::Entity::find_by_id(&name)
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
    }

    #[instrument(skip(db))]
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

    #[instrument(skip(db))]
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
}
