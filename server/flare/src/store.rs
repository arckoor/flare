use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    api::error::RestError,
    auth::{jwt::Jwt, oauth::Providers},
    config::StoreConfig,
    db::Database,
};

const IMAGE_PATH: &str = "images";

pub struct Store {
    pub image_path: PathBuf,
    pub db: Arc<Database>,
    pub jwt: Jwt,
    pub oauth: Providers,
}

impl Store {
    pub async fn new(config: StoreConfig) -> Self {
        let base_path = PathBuf::from(&config.storage.base_path);
        let image_path = base_path.join(IMAGE_PATH);

        for path in [&base_path, &image_path].into_iter() {
            if !path.exists() {
                std::fs::create_dir_all(path).expect("Failed to create storage directory");
            }
        }

        let db = Arc::new(Database::new(&config.storage).await);
        let jwt = Jwt::new(&config.jwt, db.clone());
        let providers = Providers::new(&config.oauth, db.clone());

        drop(config);

        Self {
            image_path,
            db,
            jwt,
            oauth: providers,
        }
    }

    pub fn now() -> Result<Duration, RestError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RestError::internal("Failed to get system time"))
    }
}

/*
TODO tasks
probably a task runner that lives in the Store
also set_missed_tick_behavior(Delay / Skip, depending on jitter)

tokio::spawn(async move {
    let mut interval = time::interval_at(
        time::Instant::now() + INTERVAL,
        INTERVAL,
    );
    loop {
        interval.tick().await;

        tokio::spawn(async move {
            task_to_run().await;
        });

    }
});

the following tasks should run every n minutes or so, perhaps with a bit of jitter so that they don't all run at the same time
Tasks:
- clean up old (> 1 week) group invites
- clean up old images that have not been assigned to a poll (db entry & file)
- lock old polls, so that they can't be edited anymore
- clean up votes to locked polls (set ephemeral_user_vote relation to NULL)
- clean up ephemeral users that don't have any votes left, and have not been seen in the last week or so (this is a potential race condition :c)
*/
