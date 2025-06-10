use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware,
    response::IntoResponse,
};
use axum_extra::extract::CookieJar;
use sea_orm::{ActiveValue::Set, IntoActiveModel, entity::prelude::*};
use secstr::SecUtf8;

use crate::{
    crypto::Hasher,
    store::Store,
    time::{ONE_YEAR, now},
};

use super::{error::RestError, services::extract_ip};

const COOKIE_NAME: &str = "user-id";

#[derive(Clone, Debug)]
pub struct InjectedEphemeralUser {
    pub id: i32,
}

pub async fn set_tracking_cookie(
    State(store): State<Arc<Store>>,
    mut jar: CookieJar,
    mut request: Request,
    next: middleware::Next,
) -> Result<impl IntoResponse, RestError> {
    let ip = extract_ip(&request)
        .map(|ip| Hasher::hash(ip.as_bytes()))
        .transpose()?;

    if let Some(ip) = ip {
        let mut eph_user = sea_entity::ephemeral_user::Entity::find()
            .filter(sea_entity::ephemeral_user::Column::Ip.eq(&ip))
            .one(&store.db.sea)
            .await?;

        let cookie = jar.get(COOKIE_NAME).map(|c| c.value().to_string());
        if eph_user.is_none() && cookie.is_some() {
            eph_user = sea_entity::ephemeral_user::Entity::find()
                .filter(sea_entity::ephemeral_user::Column::Cookie.eq(cookie.as_ref().unwrap()))
                .one(&store.db.sea)
                .await?;
        }
        let cookie = cookie.unwrap_or(cuid2::create_id());

        if eph_user.is_none() {
            eph_user = Some(
                sea_entity::ephemeral_user::ActiveModel {
                    ip: Set(ip.clone()),
                    cookie: Set(cookie.clone()),
                    ..Default::default()
                }
                .insert(&store.db.sea)
                .await?,
            );
        }
        let eph_user = eph_user.unwrap();
        let eph_user_id = eph_user.id;

        let previous_ip = eph_user.ip.clone();
        let mut eph_user = eph_user.into_active_model();
        eph_user.last_seen_at = Set(now().as_secs_f64());
        if previous_ip != ip {
            eph_user.ip = Set(ip.clone());
        }
        eph_user.update(&store.db.sea).await?;

        let cookie = store.jwt.build_cookie(
            COOKIE_NAME.to_string(),
            &SecUtf8::from(cookie),
            ONE_YEAR,
            false,
        );
        jar = jar.add(cookie);

        request.extensions_mut().insert(jar.clone());
        request
            .extensions_mut()
            .insert(InjectedEphemeralUser { id: eph_user_id });
    } else {
        tracing::warn!("No IP found in request headers");
        return Err(RestError::bad_req("No client ip present"));
    }

    let response = next.run(request).await;

    Ok((jar, response))
}
