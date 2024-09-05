use std::sync::Arc;

use oauth2::{
    basic::{self},
    url::Url,
    Client, CsrfToken, PkceCodeChallenge,
};
use redis::AsyncCommands;
use secstr::{SecStr, SecUtf8};

use crate::{api::error::FoundError, crypto::PkceCipher, db::Database};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct OAuthState {
    pkce_verifier: String,
    redirect_uri: String,
}

pub trait OAuthProvider {
    fn new(client_id: &SecUtf8, client_secret: &SecUtf8, login_url: String) -> Self;
    fn auth_url(&self, csrf: CsrfToken, challenge: PkceCodeChallenge) -> Url;
    fn callback(
        &self,
        code: String,
        verifier: String,
    ) -> impl std::future::Future<Output = Result<(i64, String), FoundError>> + Send;
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
    pkce_cipher: PkceCipher,
    login_url: String,
    db: Arc<Database>,
}

impl<T: OAuthProvider> OAuth<T> {
    pub fn new(
        client_id: &SecUtf8,
        client_secret: &SecUtf8,
        pkce_secret: &SecStr,
        login_url: &str,
        db: Arc<Database>,
    ) -> Self {
        let provider = T::new(client_id, client_secret, login_url.to_owned());

        let pkce_cipher = PkceCipher::new(pkce_secret);
        Self {
            provider,
            pkce_cipher,
            login_url: login_url.to_owned(),
            db,
        }
    }

    pub async fn auth_url(&self, redirect_uri: String) -> Result<Url, FoundError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let encrypted_pkce_verifier = self.pkce_cipher.encrypt(pkce_verifier.secret().as_bytes());

        let csrf_token = CsrfToken::new_random();

        let state = OAuthState {
            pkce_verifier: encrypted_pkce_verifier,
            redirect_uri,
        };
        let state_key = format!("oauth:{}", csrf_token.secret());

        // TODO errors need to include an actual error type
        let mut con = self
            .db
            .redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| FoundError::new(&self.login_url, "".to_string()))?;

        con.set_ex(
            state_key,
            serde_json::to_string(&state).expect("Failed to serialize OAuthState"),
            60 * 5,
        )
        .await
        .map_err(|_| FoundError::new(&self.login_url, "".to_string()))?;

        Ok(self.provider.auth_url(csrf_token, pkce_challenge))
    }

    pub async fn callback(
        &self,
        code: String,
        state: String,
    ) -> Result<(i64, String, String), FoundError> {
        let state_key = format!("oauth:{}", state);
        let mut con = self
            .db
            .redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| FoundError::new(&self.login_url, "".to_string()))?;

        let state: String = con
            .get_del(&state_key)
            .await
            .map_err(|_| FoundError::new(&self.login_url, "".to_string()))?;

        let oauth_state: OAuthState =
            serde_json::from_str(&state).expect("Failed to parse OAuthState");

        let decrypted_verifier =
            String::from_utf8(self.pkce_cipher.decrypt(&oauth_state.pkce_verifier))
                .expect("Failed to decrypt verifier");

        let (id, username) = self.provider.callback(code, decrypted_verifier).await?;
        Ok((id, username, oauth_state.redirect_uri))
    }

    pub fn login_url(&self) -> &str {
        &self.login_url
    }
}
