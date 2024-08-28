use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

use crate::crypto::deserialize_secutf8;

#[derive(Deserialize)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct LoginInfo {
    pub username: String,
    #[serde(deserialize_with = "deserialize_secutf8")]
    pub password: SecUtf8,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct TokenResponse {
    pub access: String,
}
