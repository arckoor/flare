use std::{path::PathBuf, time::Duration};

use secstr::{SecStr, SecUtf8};
use serde::Deserialize;

use crate::{
    crypto::secstr::{deserialize_secstr_hex, deserialize_secutf8},
    time::{ONE_DAY, ONE_HOUR, ONE_MONTH},
};

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let duration_str = String::deserialize(deserializer)?;

    // Parse strings like "24h" or "7d"
    let len = duration_str.len();
    let (value, unit) = duration_str.split_at(len - 1);
    let value = value.parse::<u64>().map_err(serde::de::Error::custom)?;

    let delta = match unit {
        "h" => Duration::from_secs(value * (ONE_HOUR as u64)),
        "d" => Duration::from_secs(value * (ONE_DAY as u64)),
        _ => return Err(serde::de::Error::custom("duration must end with h or d")),
    };

    Ok(delta)
}

#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    pub discord_id: Option<String>,
    pub github_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    pub base_path: PathBuf,
    pub postgres_url: String,
    pub valkey_url: String,
    pub admin: AdminConfig,
}

#[derive(Debug, Deserialize)]
pub struct JwtConfig {
    #[serde(deserialize_with = "deserialize_duration")]
    pub access_expiry: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub refresh_expiry: Duration,
    #[serde(deserialize_with = "deserialize_secutf8")]
    pub access_kek: SecUtf8,
    #[serde(deserialize_with = "deserialize_secutf8")]
    pub refresh_kek: SecUtf8,
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuthConfig {
    pub discord: OAuthProvider,
    pub github: OAuthProvider,
    #[serde(deserialize_with = "deserialize_secstr_hex")]
    pub pkce_secret: SecStr,
    // TODO this could maybe be a URL?
    pub login_url: String,
    pub api_base: String,
    pub user_agent: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuthProvider {
    #[serde(deserialize_with = "deserialize_secutf8")]
    pub client_id: SecUtf8,
    #[serde(deserialize_with = "deserialize_secutf8")]
    pub client_secret: SecUtf8,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    #[serde(deserialize_with = "deserialize_secutf8")]
    pub mtls_kek: SecUtf8,
    pub mtls_external: PathBuf,
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

pub fn config(base: &str) -> FlareConfig {
    let config = config::Config::builder()
        .add_source(config::File::with_name(base))
        .build()
        .expect("Failed to load config");

    config
        .try_deserialize::<FlareConfig>()
        .expect("Failed to deserialize config")
}

impl Default for FlareConfig {
    fn default() -> Self {
        FlareConfig {
            store: StoreConfig {
                storage: StorageConfig {
                    base_path: PathBuf::from("./data"),
                    postgres_url: "postgresql://flare:flare@localhost:5432/flare-db".to_string(),
                    valkey_url: "redis://localhost:6379".to_string(),
                    admin: AdminConfig {
                        discord_id: Some("flare-0".to_string()),
                        github_id: Some("flare-1".to_string()),
                    },
                },
                jwt: JwtConfig {
                    access_expiry: Duration::from_secs(ONE_HOUR as u64),
                    refresh_expiry: Duration::from_secs(ONE_MONTH as u64),
                    access_kek: SecUtf8::from(""),
                    refresh_kek: SecUtf8::from(""),
                    domain: "localhost".to_string(),
                },
                oauth: OAuthConfig {
                    discord: OAuthProvider {
                        client_id: SecUtf8::from(""),
                        client_secret: SecUtf8::from(""),
                    },
                    github: OAuthProvider {
                        client_id: SecUtf8::from(""),
                        client_secret: SecUtf8::from(""),
                    },
                    pkce_secret: SecStr::from("00000000000000000000000000000000"),
                    login_url: "https://localhost/login".to_string(),
                    api_base: "https://localhost/api".to_string(),
                    user_agent: "change-me".to_string(),
                },
            },
            server: ServerConfig {
                port: 8080,
                mtls_external: PathBuf::from("./certs"),
                mtls_kek: SecUtf8::from(""),
            },
        }
    }
}
