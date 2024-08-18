use crate::{
    api::{api_params::LoginInfo, error::RestError},
    prisma::{credential_user, discord_user, user, Permissions, PrismaClient},
};

pub struct Database {
    pub prisma: PrismaClient,
    pub redis: redis::Client,
}

impl Database {
    pub async fn new() -> Self {
        let prisma = PrismaClient::_builder()
            .build()
            .await
            .expect("Failed to create Prisma client");

        #[cfg(all(not(debug_assertions), not(feature = "sim")))]
        prisma
            ._migrate_deploy()
            .await
            .expect("Failed to migrate database");

        #[cfg(debug_assertions)]
        {
            #[cfg(feature = "sim")]
            prisma
                ._db_push()
                .accept_data_loss()
                .force_reset()
                .await
                .expect("Failed to push database");
            #[cfg(not(feature = "sim"))]
            prisma
                ._db_push()
                .accept_data_loss()
                .await
                .expect("Failed to push database");
        }

        let redis = redis::Client::open(dotenv::var("REDIS_URL").expect("REDIS_URL must be set"))
            .expect("Failed to create Redis client");
        #[cfg(feature = "sim")]
        {
            let mut con = redis
                .get_multiplexed_async_connection()
                .await
                .expect("Failed to get Redis connection");
            redis::cmd("FLUSHDB")
                .exec_async(&mut con)
                .await
                .expect("Failed to flush Redis database");
        }

        Self { prisma, redis }
    }

    pub async fn create_credentials_user(
        &self,
        login_info: LoginInfo,
    ) -> Result<user::Data, RestError> {
        self.prisma
            ._transaction()
            .run(|client| async move {
                let user = client
                    .user()
                    .create(
                        login_info.username.clone(),
                        vec![user::permissions::set(vec![Permissions::CreatePolls])],
                    )
                    .exec()
                    .await?;
                client
                    .credential_user()
                    .create(
                        user::id::equals(user.id),
                        login_info.username.clone(),
                        login_info.password.clone(),
                        vec![],
                    )
                    .exec()
                    .await?;

                Ok::<_, RestError>(user)
            })
            .await
    }

    pub async fn get_user(&self, id: i32) -> Result<Option<user::Data>, RestError> {
        Ok(self
            .prisma
            .user()
            .find_unique(user::id::equals(id))
            .exec()
            .await?)
    }

    pub async fn get_credential_user(
        &self,
        username: String,
    ) -> Result<Option<credential_user::Data>, RestError> {
        let u = self
            .prisma
            .credential_user()
            .find_unique(credential_user::username::equals(username))
            .with(credential_user::user::fetch())
            .exec()
            .await?;
        Ok(u)
    }

    pub async fn get_or_create_discord_user(
        &self,
        discord_id: i64,
        discord_username: String,
    ) -> Result<Box<user::Data>, RestError> {
        let user = self
            .prisma
            .discord_user()
            .find_unique(discord_user::discord_id::equals(discord_id))
            .with(discord_user::user::fetch())
            .exec()
            .await?;
        let user = match user {
            Some(user) => user
                .user
                .expect("Every discord user must be related to a user"),
            None => {
                self.prisma
                    ._transaction()
                    .run(|client| async move {
                        let user = client
                            .user()
                            .create(
                                discord_username,
                                vec![user::permissions::set(vec![Permissions::CreatePolls])],
                            )
                            .exec()
                            .await?;

                        client
                            .discord_user()
                            .create(user::id::equals(user.id), discord_id, vec![])
                            .exec()
                            .await?;

                        Ok::<_, RestError>(Box::new(user))
                    })
                    .await?
            }
        };
        Ok(user)
    }
}
