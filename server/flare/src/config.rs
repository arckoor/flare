use std::path::PathBuf;

use secstr::{SecStr, SecUtf8};
use serde::Deserialize;

use crate::crypto::{deserialize_secstr, deserialize_secutf8};

#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    pub base_path: PathBuf,
    pub database_url: String,
    pub redis_url: String,
}

#[derive(Debug, Deserialize)]
pub struct JwtConfig {
    #[serde(deserialize_with = "deserialize_secstr")]
    pub access_secret: SecStr,
    #[serde(deserialize_with = "deserialize_secstr")]
    pub refresh_secret: SecStr,
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuthConfig {
    #[serde(deserialize_with = "deserialize_secutf8")]
    pub discord_client_id: SecUtf8,
    #[serde(deserialize_with = "deserialize_secutf8")]
    pub discord_client_secret: SecUtf8,
    #[serde(deserialize_with = "deserialize_secstr")]
    pub pkce_secret: SecStr,
    pub login_url: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    pub cert_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    pub storage: StorageConfig,
    pub jwt: JwtConfig,
    pub oauth: OAuthConfig,
}

#[derive(Debug, Deserialize)]
pub struct FlareConfig {
    pub store: StoreConfig,
    pub server: ServerConfig,
}

pub fn config() -> FlareConfig {
    let config = config::Config::builder()
        .add_source(config::File::with_name("config"))
        .build()
        .expect("Failed to load config");

    config
        .clone()
        .try_deserialize::<FlareConfig>()
        .expect("Failed to deserialize config")
}

impl Default for FlareConfig {
    fn default() -> Self {
        FlareConfig {
            store: StoreConfig {
                storage: StorageConfig {
                    base_path: PathBuf::from("./data"),
                    database_url: "postgresql://flare:flare@localhost:5432/flare-db".to_string(),
                    redis_url: "redis://localhost:6379".to_string(),
                },
                jwt: JwtConfig {
                    access_secret: SecStr::from(""),
                    refresh_secret: SecStr::from(""),
                    domain: "localhost".to_string(),
                },
                oauth: OAuthConfig {
                    discord_client_id: SecUtf8::from(""),
                    discord_client_secret: SecUtf8::from(""),
                    pkce_secret: SecStr::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
                    login_url: "/login".to_string(),
                },
            },
            server: ServerConfig {
                port: 8080,
                cert_path: PathBuf::from("./certs"),
            },
        }
    }
}
