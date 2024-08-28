use std::{path::PathBuf, sync::Arc};

use crate::{
    auth::{discord_oauth::DiscordOAuth, jwt::Jwt, oauth::OAuth},
    config::StoreConfig,
    db::Database,
};

pub struct Store {
    pub base_path: PathBuf,
    pub db: Arc<Database>,
    pub jwt: Jwt,
    pub d_oauth: OAuth<DiscordOAuth>,
}

impl Store {
    pub async fn new(config: StoreConfig) -> Self {
        let base_path = PathBuf::from(&config.storage.base_path);

        let db = Arc::new(Database::new(&config).await);

        let refresh_expiry = chrono::Duration::days(30); // TODO config
        let access_expiry = chrono::Duration::hours(1);

        let jwt = Jwt::new(
            config.jwt.domain.clone(),
            &config.jwt.access_secret,
            &config.jwt.refresh_secret,
            db.clone(),
            access_expiry,
            refresh_expiry,
        );

        let d_oauth = OAuth::new(
            &config.oauth.discord_client_id,
            &config.oauth.discord_client_secret,
            db.clone(),
        );

        drop(config);

        Self {
            base_path,
            db,
            jwt,
            d_oauth,
        }
    }
}
