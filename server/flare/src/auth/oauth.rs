use std::sync::Arc;

use oauth2::{
    basic::{self},
    url::Url,
    Client, CsrfToken, PkceCodeChallenge,
};
use redis::AsyncCommands;
use secstr::SecUtf8;

use crate::{api::error::RestError, db::Database};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct OAuthState {
    pkce_verifier: String,
    redirect_uri: String,
}

pub trait OAuthProvider {
    fn new(client_id: &SecUtf8, client_secret: &SecUtf8) -> Self;
    fn auth_url(&self, csrf: CsrfToken, challenge: PkceCodeChallenge) -> Url;
    fn callback(
        &self,
        code: String,
        verifier: String,
    ) -> impl std::future::Future<Output = Result<(i64, String), RestError>> + Send;
}

pub type OAuthClient = Client<
    oauth2::StandardErrorResponse<basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, basic::BasicTokenType>,
    basic::BasicTokenType,
    oauth2::StandardTokenIntrospectionResponse<
        oauth2::EmptyExtraTokenFields,
        basic::BasicTokenType,
    >,
    oauth2::StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
>;

pub struct OAuth<T: OAuthProvider> {
    provider: T,
    db: Arc<Database>,
}
impl<T: OAuthProvider> OAuth<T> {
    pub fn new(client_id: &SecUtf8, client_secret: &SecUtf8, db: Arc<Database>) -> Self {
        let provider = T::new(client_id, client_secret);
        Self { provider, db }
    }
    pub async fn auth_url(&self, redirect_uri: String) -> Result<Url, RestError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let csrf_token = CsrfToken::new_random();

        let state = OAuthState {
            pkce_verifier: pkce_verifier.secret().clone(), // todo encrypt me
            redirect_uri,
        };
        let state_key = format!("oauth:{}", csrf_token.secret());

        let mut con = self
            .db
            .redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| RestError::internal("Failed to get redis connection"))?;

        con.set_ex(
            state_key,
            serde_json::to_string(&state).expect("Failed to serialize OAuthState"),
            60 * 5,
        )
        .await
        .map_err(|_| RestError::internal("Failed to set state"))?;

        Ok(self.provider.auth_url(csrf_token, pkce_challenge))
    }

    pub async fn callback(
        &self,
        code: String,
        state: String,
    ) -> Result<(i64, String, String), RestError> {
        let state_key = format!("oauth:{}", state);
        let mut con = self
            .db
            .redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| RestError::internal("Failed to get redis connection"))?;

        let state: String = con
            .get_del(&state_key)
            .await
            .map_err(|_| RestError::bad_req("Invalid parameters"))?; // TODO better error - it's either not present at all or expired
                                                                     // TODO this needs to redirect, else you're stuck on the callback page

        let oauth_state: OAuthState =
            serde_json::from_str(&state).expect("Failed to parse OAuthState");

        // TODO, also make it a SecStr
        let decrypted_verifier = oauth_state.pkce_verifier;

        let (id, username) = self.provider.callback(code, decrypted_verifier).await?;
        Ok((id, username, oauth_state.redirect_uri))
    }
}
