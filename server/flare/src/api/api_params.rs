use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct LoginInfo {
    pub username: String,
    pub password: String, // TODO this could be a SecStr
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct TokenResponse {
    pub access: String,
}
