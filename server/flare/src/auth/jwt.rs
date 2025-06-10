use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

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

use crate::{api::error::RestError, config::JwtConfig, db::Database, time::now};

pub const REFRESH_TOKEN: &str = "refresh-token";
pub const REFRESH_INDICATOR: &str = "refresh-indicator";

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
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
}

impl JWTSettings {
    pub fn new(passphrase: &SecUtf8, path: &Path, name: &str) -> Self {
        let (priv_, pub_) = Self::load_keys(passphrase, path, name).unwrap();
        Self {
            encoding_key: EncodingKey::from_ed_pem(priv_.unsecure()).unwrap(),
            decoding_key: DecodingKey::from_ed_pem(pub_.unsecure()).unwrap(),
        }
    }

    fn load_keys(
        passphrase: &SecUtf8,
        path: &Path,
        name: &str,
    ) -> Result<(SecStr, SecStr), RestError> {
        let p = path.join(format!("{name}.key"));
        if !std::fs::exists(&p)? {
            Self::generate_keys(passphrase, path, name)?;
        }
        let pem = std::fs::read_to_string(p)?;
        let prv = botan::Privkey::load_encrypted_pem(&pem, passphrase.unsecure())?;
        Ok((
            SecStr::new(prv.pem_encode()?.as_bytes().to_vec()),
            SecStr::new(prv.pubkey()?.pem_encode()?.as_bytes().to_vec()),
        ))
    }

    fn generate_keys(passphrase: &SecUtf8, path: &Path, name: &str) -> Result<(), RestError> {
        let mut rng = botan::RandomNumberGenerator::new_system()?;
        let prv = botan::Privkey::create("Ed25519", "", &mut rng)?
            .pem_encode_encrypted(passphrase.unsecure(), &mut rng)?;
        let path = path.join(format!("{name}.key"));
        std::fs::write(path, prv)?;
        Ok(())
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
    const ALGO_NAME: Algorithm = Algorithm::EdDSA;
    const ACCESS_PREFIX: &'static str = "access";
    const REFRESH_PREFIX: &'static str = "refresh";

    pub fn new(config: &JwtConfig, path: PathBuf, db: Arc<Database>) -> Self {
        let access = JWTSettings::new(&config.access_passphrase, &path, "access");
        let refresh = JWTSettings::new(&config.refresh_passphrase, &path, "refresh");

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
        let refresh_token = match jar.get(REFRESH_TOKEN) {
            Some(token) => token.value(),
            None => return Err(RestError::unauthorized("No refresh token found")),
        };

        let claims = jsonwebtoken::decode::<RefreshClaims>(
            refresh_token,
            &self.refresh.decoding_key,
            &Validation::new(Self::ALGO_NAME),
        )
        .map_err(|_| RestError::unauthorized("Invalid token"))?
        .claims;

        self.check_expiry(Self::REFRESH_PREFIX, &claims.sub, claims.iat)
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

    pub async fn revoke_refresh(&self, id: &str) -> Result<(), RestError> {
        let (now, refresh_expiry) = self.generate_time(self.refresh_expiry);
        self.set_nbf(Self::REFRESH_PREFIX, id, refresh_expiry, now + 120)
            .await?;
        Ok(())
    }

    pub async fn revoke_access(&self, id: &str) -> Result<(), RestError> {
        let (now, access_expiry) = self.generate_time(self.access_expiry);
        self.set_nbf(Self::ACCESS_PREFIX, id, access_expiry, now + 120)
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

    #[cfg(not(feature = "fuzz"))]
    pub async fn validate(
        &self,
        auth: Authorization<Bearer>,
        permissions: &[Permissions],
    ) -> Result<AccessClaims, RestError> {
        let claims = self.decode_access(auth.token()).await?;
        for permission in permissions {
            if !claims.permissions.contains(permission) {
                return Err(RestError::forbidden(format!(
                    "You are missing a required permission: {permission:?}"
                )));
            }
        }

        Ok(claims)
    }

    #[cfg(feature = "fuzz")]
    pub async fn validate(
        &self,
        _auth: Authorization<Bearer>,
        _permissions: &[Permissions],
    ) -> Result<AccessClaims, RestError> {
        use sea_orm::Iterable;

        return Ok(AccessClaims {
            sub: "fuzz".to_string(),
            permissions: Permissions::iter().collect(),
            groups: sea_entity::group_user::Entity::find()
                .all(&self.db.sea)
                .await?
                .into_iter()
                .map(|group| group.group_id)
                .collect(),
            exp: u64::MAX,
            iat: 0,
        });
    }

    async fn generate_refresh_token(
        &self,
        user: &sea_entity::user::Model,
    ) -> Result<SecUtf8, RestError> {
        let header = Header::new(Self::ALGO_NAME);
        let (now, expiration) = self.generate_time(self.refresh_expiry);

        let claims = RefreshClaims {
            sub: user.id.to_string(),
            exp: expiration,
            iat: now,
        };

        self.set_nbf(Self::REFRESH_PREFIX, &user.id, expiration, now)
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
        let header = Header::new(Self::ALGO_NAME);
        let (now, expiration) = self.generate_time(self.access_expiry);

        self.set_nbf(Self::ACCESS_PREFIX, &user.id, expiration, now)
            .await?;

        let groups = sea_entity::group_user::Entity::find()
            .filter(sea_entity::group_user::Column::UserId.contains(&user.id))
            .all(&self.db.sea)
            .await?
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
            &Validation::new(Self::ALGO_NAME),
        )
        .map_err(|_| RestError::unauthorized("Invalid token"))?
        .claims;

        self.check_expiry(Self::ACCESS_PREFIX, &claims.sub, claims.iat)
            .await?;

        Ok(claims)
    }

    // TODO this could be an associated function
    fn generate_time(&self, exp: Duration) -> (u64, u64) {
        let now = now();

        let expiration = (now + exp).as_secs();
        let now = now.as_secs();
        (now, expiration)
    }

    // TODO we use this elsewhere, it doesn't really belong here
    // the domain is also only used for this, so it can go to a separate struct too
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
        let token = self.build_cookie(REFRESH_TOKEN.to_string(), token, expiry, true);

        let indicator = self.build_cookie(
            REFRESH_INDICATOR.to_string(),
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
            .valkey
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
            .valkey
            .clone()
            .set_ex::<_, _, ()>(key, nbf, expiry)
            .await
            .map_err(|_| RestError::internal("Failed to set expiry"))?;
        Ok(())
    }

    async fn check_expiry(&self, prefix: &str, id: &str, iat: u64) -> Result<(), RestError> {
        let expiry = self.get_nbf(prefix, id).await?;
        if let Some(expiry) = expiry {
            if expiry > iat {
                return Err(RestError::forbidden("Token has been revoked"));
            }
        }

        Ok(())
    }
}
