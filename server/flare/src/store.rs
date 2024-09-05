use std::{path::PathBuf, sync::Arc};

use crate::{
    auth::{discord_oauth::DiscordOAuth, jwt::Jwt, oauth::OAuth},
    config::StoreConfig,
    db::Database,
};

const IMAGE_PATH: &str = "images";

pub struct Store {
    pub image_path: PathBuf,
    pub db: Arc<Database>,
    pub jwt: Jwt,
    pub d_oauth: OAuth<DiscordOAuth>,
}

impl Store {
    pub async fn new(config: StoreConfig) -> Self {
        let base_path = PathBuf::from(&config.storage.base_path);
        let image_path = base_path.join(IMAGE_PATH);

        for path in [&base_path, &image_path].iter() {
            if !path.exists() {
                std::fs::create_dir_all(path).expect("Failed to create storage directory");
            }
        }

        let db = Arc::new(Database::new(&config).await);

        let refresh_expiry = chrono::Duration::days(30); // TODO config
        let access_expiry = chrono::Duration::hours(1);

        let jwt = Jwt::new(
            config.jwt.domain.clone(),
            &config.jwt.access_secret,
            &config.jwt.refresh_secret,
            access_expiry,
            refresh_expiry,
            db.clone(),
        );

        let d_oauth = OAuth::new(
            &config.oauth.discord_client_id,
            &config.oauth.discord_client_secret,
            &config.oauth.pkce_secret,
            &config.oauth.login_url,
            db.clone(),
        );

        drop(config);

        Self {
            image_path,
            db,
            jwt,
            d_oauth,
        }
    }
}
