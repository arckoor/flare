use chrono::{DateTime, Utc};
use secstr::SecStr;
use serde::{Deserialize, Serialize};

use crate::crypto::{deserialize_secstr, serialize_secstr};

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct LoginInfo {
    pub username: String,
    #[serde(
        deserialize_with = "deserialize_secstr",
        serialize_with = "serialize_secstr"
    )]
    #[cfg_attr(feature = "api-doc", schema(value_type = String))]
    pub password: SecStr,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct TokenResponse {
    pub access: String,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct UploadedImage {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct CreatePoll {
    pub title: String,
    pub info: String,
    pub ends: DateTime<Utc>,
    pub images: Vec<String>,
}
