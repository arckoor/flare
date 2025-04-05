use std::{sync::Arc, time::Duration};

use axum_extra::{
    extract::CookieJar,
    headers::{Authorization, authorization::Bearer},
};
use cookie::Cookie;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use redis::AsyncCommands;
use sea_entity::sea_orm_active_enums::Permissions;
use sea_orm::entity::prelude::*;
use secstr::{SecStr, SecUtf8};
use serde::{Deserialize, Serialize};

use crate::{api::error::RestError, config::JwtConfig, db::Database, util::now};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub permissions: Vec<Permissions>,
    pub groups: Vec<String>,
    pub exp: u64,
    pub iat: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    sub: String,
    exp: u64,
    iat: u64,
}

struct JWTSettings {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

impl JWTSettings {
    pub fn new(secret: &SecStr) -> Self {
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
    #[cfg_attr(feature = "sim", allow(unused))]
    domain: String,
    access: JWTSettings,
    refresh: JWTSettings,
    access_expiry: Duration,
    refresh_expiry: Duration,
    db: Arc<Database>,
}

impl Jwt {
    const REFRESH_PREFIX: &'static str = "refresh";
    const ACCESS_PREFIX: &'static str = "access";
    pub const REFRESH_TOKEN: &'static str = "refresh-token";
    pub const REFRESH_INDICATOR: &'static str = "refresh-indicator";

    pub fn new(config: &JwtConfig, db: Arc<Database>) -> Self {
        let access = JWTSettings::new(&config.access_secret);
        let refresh = JWTSettings::new(&config.refresh_secret);

        Self {
            domain: config.domain.to_string(),
            access,
            refresh,
            access_expiry: config.access_expiry,
            refresh_expiry: config.refresh_expiry,
            db,
        }
    }

    pub async fn login(
        &self,
        user: &sea_entity::user::Model,
        jar: CookieJar,
    ) -> Result<(SecUtf8, CookieJar), RestError> {
        let access = self.generate_access_token(user).await?;
        let refresh = self.generate_refresh_token(user).await?;
        let jar = self.add_cookie(refresh, jar);
        Ok((access, jar))
    }

    pub async fn refresh(&self, jar: CookieJar) -> Result<(SecUtf8, CookieJar), RestError> {
        let refresh_token = match jar.get(Jwt::REFRESH_TOKEN) {
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

        self.check_expiry(Jwt::REFRESH_PREFIX, &claims.sub, claims.iat)
            .await?;

        let user = sea_entity::user::Entity::find_by_id(&claims.sub)
            .one(&self.db.sea)
            .await?;

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

    // todo should this really be public?
    pub async fn revoke_refresh(&self, id: &str) -> Result<(), RestError> {
        let (now, refresh_expiry) = self.generate_time(self.refresh_expiry)?;
        self.set_nbf(Jwt::REFRESH_PREFIX, id, refresh_expiry, now + 120)
            .await?;
        Ok(())
    }

    pub async fn revoke_access(&self, id: &str) -> Result<(), RestError> {
        let (now, access_expiry) = self.generate_time(self.access_expiry)?;
        self.set_nbf(Jwt::ACCESS_PREFIX, id, access_expiry, now + 120)
            .await?;
        Ok(())
    }

    pub async fn revoke(&self, id: &str, jar: CookieJar) -> Result<CookieJar, RestError> {
        self.revoke_refresh(id).await?;
        self.revoke_access(id).await?;

        let (token, indicator) =
            self.build_refresh_cookies(&SecUtf8::from(""), self.refresh_expiry.as_secs_f64());

        let jar = jar.remove(token).remove(indicator);

        Ok(jar)
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
                    "You are missing a required permission: {permission:?}"
                )));
            }
        }

        Ok(claims)
    }

    async fn generate_refresh_token(
        &self,
        user: &sea_entity::user::Model,
    ) -> Result<SecUtf8, RestError> {
        let header = Header::new(self.refresh.algorithm);
        let (now, expiration) = self.generate_time(self.refresh_expiry)?;

        let claims = RefreshClaims {
            sub: user.id.to_string(),
            exp: expiration,
            iat: now,
        };

        self.set_nbf(Jwt::REFRESH_PREFIX, &user.id, expiration, now)
            .await?;

        let token = SecUtf8::from(
            jsonwebtoken::encode(&header, &claims, &self.refresh.encoding_key)
                .map_err(|_| RestError::internal("Failed to create token"))?,
        );
        Ok(token)
    }

    async fn generate_access_token(
        &self,
        user: &sea_entity::user::Model,
    ) -> Result<SecUtf8, RestError> {
        let header = Header::new(self.access.algorithm);
        let (now, expiration) = self.generate_time(self.access_expiry)?;

        self.set_nbf(Jwt::ACCESS_PREFIX, &user.id, expiration, now)
            .await?;

        let groups = sea_entity::group_user::Entity::find()
            .filter(sea_entity::group_user::Column::UserId.contains(&user.id))
            .all(&self.db.sea)
            .await
            .map_err(|_| RestError::internal("Failed to get groups"))?
            .into_iter()
            .map(|group| group.group_id)
            .collect();

        let claims = AccessClaims {
            sub: user.id.to_string(),
            permissions: user.permissions.clone(),
            groups,
            exp: expiration,
            iat: now,
        };

        let token = SecUtf8::from(
            jsonwebtoken::encode(&header, &claims, &self.access.encoding_key)
                .map_err(|_| RestError::internal("Failed to create token"))?,
        );
        Ok(token)
    }

    async fn decode_access(&self, token: &str) -> Result<AccessClaims, RestError> {
        let claims = jsonwebtoken::decode::<AccessClaims>(
            token,
            &self.access.decoding_key,
            &Validation::new(self.access.algorithm),
        )
        .map_err(|_| RestError::unauthorized("Invalid token"))?
        .claims;

        self.check_expiry(Jwt::ACCESS_PREFIX, &claims.sub, claims.iat)
            .await?;

        Ok(claims)
    }

    // TODO this could be an associated function
    fn generate_time(&self, exp: Duration) -> Result<(u64, u64), RestError> {
        let now = now()?;

        let expiration = (now + exp).as_secs();
        let now = now.as_secs();
        Ok((now, expiration))
    }

    pub fn build_cookie(
        &self,
        name: String,
        value: &SecUtf8,
        expiry: f64,
        http_only: bool,
    ) -> Cookie<'static> {
        let mut builder = Cookie::build((name, value.unsecure().to_string()))
            .path("/api/")
            .secure(true)
            .same_site(cookie::SameSite::Strict)
            .max_age(cookie::time::Duration::seconds_f64(expiry));

        if http_only {
            builder = builder.http_only(true);
        }
        #[cfg(not(feature = "sim"))]
        let builder = builder.domain(self.domain.clone());
        builder.build()
    }

    fn build_refresh_cookies(
        &self,
        token: &SecUtf8,
        expiry: f64,
    ) -> (Cookie<'static>, Cookie<'static>) {
        let token = self.build_cookie(Jwt::REFRESH_TOKEN.to_string(), token, expiry, true);

        let indicator = self.build_cookie(
            Jwt::REFRESH_INDICATOR.to_string(),
            &SecUtf8::from("true"),
            expiry,
            false,
        );

        (token, indicator)
    }

    fn add_cookie(&self, token: SecUtf8, jar: CookieJar) -> CookieJar {
        let (token, indicator) =
            self.build_refresh_cookies(&token, self.refresh_expiry.as_secs_f64());

        jar.add(token).add(indicator)
    }

    async fn get_nbf(&self, prefix: &str, id: &str) -> Result<Option<u64>, RestError> {
        let key = format!("jwt:{prefix}:{id}");
        self.db
            .redis
            .clone()
            .get(key)
            .await
            .map_err(|_| RestError::internal("Failed to get expiry"))
    }

    async fn set_nbf(
        &self,
        prefix: &str,
        id: &str,
        expiry: u64,
        nbf: u64,
    ) -> Result<(), RestError> {
        let key = format!("jwt:{prefix}:{id}");

        let expiry = (Duration::from_secs(expiry) - Duration::from_secs(nbf)
            + Duration::new(10, 0))
        .as_secs();

        self.db
            .redis
            .clone()
            .set_ex::<_, _, ()>(key, nbf, expiry)
            .await
            .map_err(|_| RestError::internal("Failed to set expiry"))?;
        Ok(())
    }

    async fn check_expiry(&self, prefix: &str, id: &str, iat: u64) -> Result<(), RestError> {
        let expiry = self.get_nbf(prefix, id).await?;
        if let Some(expiry) = expiry {
            let expiry = Duration::from_secs(expiry);
            let iat = Duration::from_secs(iat);
            if expiry > iat {
                return Err(RestError::unauthorized("Token has been revoked"));
            }
        }

        Ok(())
    }
}
