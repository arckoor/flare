use std::{path::PathBuf, sync::Arc};

use crate::{
    auth::{jwt::Jwt, oauth::OAuth},
    config::StoreConfig,
    db::Database,
};

pub struct Store {
    pub image_path: PathBuf,
    pub cert_path: PathBuf,
    pub db: Arc<Database>,
    pub jwt: Jwt,
    pub oauth: OAuth,
}

impl Store {
    const IMAGE_PATH: &str = "images";
    const JWT_PATH: &str = "jwt";
    const CERT_PATH: &str = "certs";

    pub async fn new(config: StoreConfig) -> Self {
        let base_path = PathBuf::from(&config.storage.base_path);
        let image_path = base_path.join(Self::IMAGE_PATH);
        let jwt_path = base_path.join(Self::JWT_PATH);
        let cert_path = base_path.join(Self::CERT_PATH);

        for path in [&base_path, &image_path, &jwt_path, &cert_path].into_iter() {
            if !path.exists() {
                std::fs::create_dir_all(path).expect("Failed to create storage directory");
            }
        }

        let db = Arc::new(Database::new(config.storage).await);
        let jwt = Jwt::new(config.jwt, jwt_path, db.clone());
        let oauth = OAuth::new(config.oauth, db.clone());

        Self {
            image_path,
            cert_path,
            db,
            jwt,
            oauth,
        }
    }
}
