use std::{path::PathBuf, sync::Arc};

use crate::{
    auth::{discord_oauth::DiscordOAuth, jwt::Jwt},
    db::Database,
};

pub struct Store {
    pub base_path: PathBuf,
    pub db: Arc<Database>,
    pub jwt: Jwt,
    pub d_oauth: DiscordOAuth,
}

impl Store {
    pub async fn new(base_path: PathBuf) -> Self {
        dotenv::dotenv().ok();

        let db = Arc::new(Database::new().await);

        let refresh_expiry = chrono::Duration::days(30);
        let access_expiry = chrono::Duration::hours(1);

        let jwt = Jwt::new(
            secstr::SecStr::new(
                dotenv::var("ACCESS_SECRET")
                    .expect("ACCESS_SECRET must be set")
                    .into_bytes(),
            ),
            secstr::SecStr::new(
                dotenv::var("REFRESH_SECRET")
                    .expect("REFRESH_SECRET must be set")
                    .into_bytes(),
            ),
            db.clone(),
            access_expiry,
            refresh_expiry,
        );

        let d_oauth = DiscordOAuth::new(
            secstr::SecStr::new(
                dotenv::var("DISCORD_CLIENT_ID")
                    .expect("DISCORD_CLIENT_ID must be set")
                    .into_bytes(),
            ),
            secstr::SecStr::new(
                dotenv::var("DISCORD_CLIENT_SECRET")
                    .expect("DISCORD_CLIENT_SECRET must be set")
                    .into_bytes(),
            ),
            db.clone(),
        );

        Self {
            base_path,
            db,
            jwt,
            d_oauth,
        }
    }
}
