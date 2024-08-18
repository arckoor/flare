use std::sync::Arc;

use axum_extra::{
    extract::CookieJar,
    headers::{authorization::Bearer, Authorization},
};
use chrono::{self, Duration, TimeDelta};
use cookie::Cookie;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use redis::AsyncCommands;
use secstr::SecStr;
use serde::{Deserialize, Serialize};

use crate::{
    api::error::RestError,
    db::Database,
    prisma::{user::Data as User, Permissions},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: i32,
    pub permissions: Vec<Permissions>,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    sub: i32,
    exp: usize,
    iat: usize,
}

struct JWTSettings {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

impl JWTSettings {
    pub fn new(secret: SecStr) -> Self {
        let encoding_key = EncodingKey::from_secret(secret.unsecure());
        let decoding_key = DecodingKey::from_secret(secret.unsecure());
        let algorithm = Algorithm::HS512;

        Self {
            encoding_key,
            decoding_key,
            algorithm,
        }
    }
}

pub struct Jwt {
    access: JWTSettings,
    refresh: JWTSettings,
    access_expiry: Duration,
    refresh_expiry: Duration,
    db: Arc<Database>,
}

impl Jwt {
    const REFRESH_PREFIX: &'static str = "refresh";
    const ACCESS_PREFIX: &'static str = "access";

    pub fn new(
        access_secret: SecStr,
        refresh_secret: SecStr,
        db: Arc<Database>,
        access_expiry: Duration,
        refresh_expiry: Duration,
    ) -> Self {
        let access = JWTSettings::new(access_secret);
        let refresh = JWTSettings::new(refresh_secret);
        Self {
            access,
            refresh,
            access_expiry,
            refresh_expiry,
            db,
        }
    }

    async fn generate_refresh_token(&self, user: &User) -> Result<String, RestError> {
        let header = Header::new(self.refresh.algorithm);
        let (now, expiration) = self.generate_time(self.refresh_expiry);

        let claims = RefreshClaims {
            sub: user.id,
            exp: expiration,
            iat: now,
        };

        self.set_nbf(Jwt::REFRESH_PREFIX, user.id, expiration, now)
            .await?;

        let token = jsonwebtoken::encode(&header, &claims, &self.refresh.encoding_key)
            .map_err(|_| RestError::internal("Failed to create token"))?;
        Ok(token)
    }

    async fn generate_access_token(&self, user: &User) -> Result<String, RestError> {
        let header = Header::new(self.access.algorithm);
        let (now, expiration) = self.generate_time(self.access_expiry);

        let claims = AccessClaims {
            sub: user.id,
            permissions: user.permissions.clone(),
            exp: expiration,
            iat: now,
        };

        self.set_nbf(Jwt::ACCESS_PREFIX, user.id, expiration, now)
            .await?;

        let token = jsonwebtoken::encode(&header, &claims, &self.access.encoding_key)
            .map_err(|_| RestError::internal("Failed to create token"))?;
        Ok(token)
    }

    pub async fn login(
        &self,
        user: &User,
        jar: CookieJar,
    ) -> Result<(String, CookieJar), RestError> {
        let access = self.generate_access_token(user).await?;
        let refresh = self.generate_refresh_token(user).await?;
        let jar = self.add_cookie(refresh, jar);
        Ok((access, jar))
    }

    pub async fn decode_access(&self, token: &str) -> Result<AccessClaims, RestError> {
        let claims = jsonwebtoken::decode::<AccessClaims>(
            token,
            &self.access.decoding_key,
            &Validation::new(self.access.algorithm),
        )
        .map_err(|_| RestError::unauthorized("Invalid token"))?
        .claims;

        self.check_expiry(Jwt::ACCESS_PREFIX, claims.sub, claims.iat)
            .await?;

        Ok(claims)
    }

    pub async fn refresh(&self, jar: CookieJar) -> Result<(String, CookieJar), RestError> {
        let refresh_token = match jar.get("refresh_token") {
            Some(token) => token.value(),
            None => return Err(RestError::unauthorized("No refresh token found")),
        };

        let claims = jsonwebtoken::decode::<RefreshClaims>(
            refresh_token,
            &self.refresh.decoding_key,
            &Validation::new(self.refresh.algorithm),
        )
        .map_err(|_| RestError::unauthorized("Invalid token"))?
        .claims;

        self.check_expiry(Jwt::REFRESH_PREFIX, claims.sub, claims.iat)
            .await?;

        let user = self.db.get_user(claims.sub).await?;

        match user {
            Some(user) => {
                let refresh = self.generate_refresh_token(&user).await?;
                let access = self.generate_access_token(&user).await?;
                let jar = self.add_cookie(refresh, jar);
                Ok((access, jar))
            }
            None => Err(RestError::unauthorized("Invalid token")),
        }
    }

    pub async fn revoke(&self, id: i32) -> Result<(), RestError> {
        let (now, access_expiry) = self.generate_time(self.access_expiry);
        let (_, refresh_expiry) = self.generate_time(self.refresh_expiry);

        self.set_nbf(Jwt::ACCESS_PREFIX, id, access_expiry, now)
            .await?;
        self.set_nbf(Jwt::REFRESH_PREFIX, id, refresh_expiry, now)
            .await?;

        Ok(())
    }

    pub async fn validate(
        &self,
        auth: Authorization<Bearer>,
        permissions: Vec<Permissions>,
    ) -> Result<AccessClaims, RestError> {
        let claims = self.decode_access(auth.token()).await?;
        for permission in permissions {
            if !claims.permissions.contains(&permission) {
                return Err(RestError::forbidden(format!(
                    "You are missing a required permission: {:?}",
                    permission
                )));
            }
        }

        Ok(claims)
    }

    fn generate_time(&self, exp: TimeDelta) -> (usize, usize) {
        let now = chrono::Utc::now();
        let expiration = (now + exp).timestamp_millis() as usize;
        let now = now.timestamp_millis() as usize;
        (now, expiration)
    }

    fn add_cookie(&self, token: String, jar: CookieJar) -> CookieJar {
        let builder = Cookie::build(("refresh_token", token))
            .path("/api/") // todo
            .http_only(true)
            .secure(true)
            .same_site(cookie::SameSite::Strict)
            .max_age(cookie::time::Duration::minutes(
                self.refresh_expiry.num_minutes(),
            ));
        #[cfg(not(feature = "sim"))]
        let builder = builder.domain("localhost");
        let cookie = builder.build();

        jar.add(cookie)
    }

    async fn get_nbf(&self, prefix: &str, id: i32) -> Result<Option<u64>, RestError> {
        let key = format!("jwt:{prefix}:{id}");
        let mut con = self
            .db
            .redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| RestError::internal("Failed to get redis connection"))?;
        let nbf: Option<u64> = con
            .get(key)
            .await
            .map_err(|_| RestError::internal("Failed to get expiry"))?;
        Ok(nbf)
    }

    async fn set_nbf(
        &self,
        prefix: &str,
        id: i32,
        expiry: usize,
        nbf: usize,
    ) -> Result<(), RestError> {
        let key = format!("jwt:{prefix}:{id}");
        let mut con = self
            .db
            .redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| RestError::internal("Failed to get redis connection"))?;

        let expiry = (Duration::milliseconds(expiry as i64) - Duration::milliseconds(nbf as i64)
            + Duration::milliseconds(1000))
        .num_seconds() as u64;

        con.set_ex(key, nbf, expiry)
            .await
            .map_err(|_| RestError::internal("Failed to set expiry"))?;
        Ok(())
    }

    async fn check_expiry(&self, prefix: &str, id: i32, iat: usize) -> Result<(), RestError> {
        let expiry = self.get_nbf(prefix, id).await?;
        if let Some(expiry) = expiry {
            let expiry = Duration::milliseconds(expiry as i64);
            let iat = Duration::milliseconds(iat as i64);
            if expiry > iat {
                return Err(RestError::unauthorized("Token has been revoked"));
            }
        }

        Ok(())
    }
}
