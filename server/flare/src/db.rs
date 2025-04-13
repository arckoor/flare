use sea_migration::{Migrator, MigratorTrait};
use sea_orm::{
    ActiveModelTrait, DatabaseConnection, Iterable, Set, TransactionTrait, entity::prelude::*,
};

use crate::{
    api::error::RestError,
    config::{AdminConfig, StorageConfig},
    transaction,
};

pub struct Database {
    pub sea: DatabaseConnection,
    pub redis: redis::aio::MultiplexedConnection,
}

impl Database {
    pub async fn new(config: &StorageConfig) -> Self {
        let sea = sea_orm::Database::connect(&config.database_url)
            .await
            .expect("Failed to create SeaORM connection");

        let redis = redis::Client::open(config.redis_url.clone())
            .expect("Failed to create Redis client")
            .get_multiplexed_async_connection()
            .await
            .expect("Failed to get Redis connection");

        // in sim runs, we completely flush everything
        #[cfg(feature = "sim")]
        {
            Migrator::reset(&sea)
                .await
                .expect("Failed to reset database");

            redis::cmd("FLUSHDB")
                .exec_async(&mut redis.clone())
                .await
                .expect("Failed to flush Redis database");
        }

        Migrator::up(&sea, None)
            .await
            .expect("Failed to migrate database");

        Database::init_admin(config.admin.clone(), &sea).await;

        Self { sea, redis }
    }

    pub async fn get_or_create_or_link_oauth_user(
        &self,
        oauth_id: String,
        provider: sea_entity::sea_orm_active_enums::OauthProvider,
        existing_user: Option<String>,
    ) -> Result<sea_entity::user::Model, RestError> {
        let oauth_user = sea_entity::o_auth_user::Entity::find()
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::o_auth_user::Column::Provider.eq(provider))
                    .add(sea_entity::o_auth_user::Column::ProviderUserId.eq(oauth_id.clone())),
            )
            .find_also_related(sea_entity::user::Entity)
            .one(&self.sea)
            .await?;

        // TODO test this logic, am not sure about it just yet
        match oauth_user {
            Some((_, Some(user))) => {
                if let Some(existing_user) = existing_user {
                    if user.id != existing_user {
                        return Err(RestError::forbidden(
                            "This account is already linked to a user".to_string(),
                        ));
                    }
                }

                Ok(user)
            }
            None => {
                let user = transaction!(&self.sea, txn, {
                    let user = if let Some(user_id) = existing_user {
                        sea_entity::user::Entity::find_by_id(user_id)
                            .one(txn)
                            .await?
                            .ok_or_else(|| RestError::not_found("User not found"))?
                    } else {
                        sea_entity::user::ActiveModel {
                            id: Set(cuid2::create_id()),
                            permissions: Set(vec![]),
                            ..Default::default()
                        }
                        .insert(txn)
                        .await?
                    };

                    sea_entity::o_auth_user::ActiveModel {
                        provider: Set(provider),
                        provider_user_id: Set(oauth_id),
                        user_id: Set(user.id.clone()),
                        ..Default::default()
                    }
                    .insert(txn)
                    .await?;

                    Ok(user)
                })?;

                Ok(user)
            }
            Some((_, None)) => unreachable!(),
        }
    }

    pub fn filter_polls(
        user_id: &str,
        groups: Vec<String>,
        group_id: Option<String>,
    ) -> sea_orm::Condition {
        sea_orm::Condition::any()
            .add(sea_entity::poll::Column::OwnerId.eq(user_id))
            .add(sea_entity::poll::Column::GroupId.is_in(groups))
            .add_option(group_id.map(|id| sea_entity::poll::Column::GroupId.eq(id)))
    }

    pub fn filter_poll_by_id(
        poll_id: &str,
        user_id: &str,
        groups: Vec<String>,
    ) -> sea_orm::Condition {
        sea_orm::Condition::all()
            .add(sea_entity::poll::Column::Id.eq(poll_id))
            .add(Database::filter_polls(user_id, groups, None))
    }

    pub fn filter_group_user(group_id: &str, user_id: &str) -> sea_orm::Condition {
        sea_orm::Condition::all()
            .add(sea_entity::group_user::Column::GroupId.eq(group_id))
            .add(sea_entity::group_user::Column::UserId.eq(user_id))
    }

    pub fn filter_group_by_owner(group_id: &str, owner_id: &str) -> sea_orm::Condition {
        sea_orm::Condition::all()
            .add(sea_entity::group::Column::Id.eq(group_id))
            .add(sea_entity::group::Column::OwnerId.eq(owner_id))
    }

    pub async fn remove_user_from_group<C>(
        db: &C,
        group: &str,
        user: &str,
        group_owner: &str,
    ) -> Result<(), RestError>
    where
        C: ConnectionTrait,
    {
        sea_entity::group_user::Entity::delete_by_id((group.to_string(), user.to_string()))
            .exec(db)
            .await?;

        sea_entity::poll::Entity::update_many()
            .col_expr(sea_entity::poll::Column::OwnerId, Expr::value(group_owner))
            .filter(
                sea_orm::Condition::all()
                    .add(sea_entity::poll::Column::OwnerId.eq(user.to_string()))
                    .add(sea_entity::poll::Column::GroupId.eq(group)),
            )
            .exec(db)
            .await?;

        Ok(())
    }

    async fn init_admin(config: AdminConfig, sea: &DatabaseConnection) {
        if sea_entity::user::Entity::find().count(sea).await.unwrap() > 0 {
            return;
        }
        transaction!(sea, txn, {
            let admin_id = if cfg!(feature = "sim") {
                config.discord_id.clone().unwrap()
            } else {
                cuid2::create_id()
            };

            let admin = sea_entity::user::ActiveModel {
                id: Set(admin_id),
                permissions: Set(sea_entity::sea_orm_active_enums::Permissions::iter().collect()),
                ..Default::default()
            }
            .insert(txn)
            .await?;

            for (id, provider) in [
                (
                    config.discord_id,
                    sea_entity::sea_orm_active_enums::OauthProvider::Discord,
                ),
                (
                    config.github_id,
                    sea_entity::sea_orm_active_enums::OauthProvider::Github,
                ),
            ] {
                if let Some(id) = id {
                    sea_entity::o_auth_user::ActiveModel {
                        provider: Set(provider),
                        provider_user_id: Set(id.clone()),
                        user_id: Set(admin.id.clone()),
                        ..Default::default()
                    }
                    .insert(txn)
                    .await?;
                }
            }

            assert_ne!(
                sea_entity::o_auth_user::Entity::find()
                    .filter(sea_entity::o_auth_user::Column::UserId.eq(admin.id.clone()))
                    .count(txn)
                    .await?,
                0,
                "You must configure at least one login method for the admin user"
            );

            Ok(())
        })
        .expect("Failed to init admin");
    }
}

// TODO pub struct Filters {} ?
