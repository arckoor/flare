use std::sync::Arc;

use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, url::Url};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use crate::{api::error::FoundError, config::OAuthConfig, crypto::PkceCipher, db::Database};

use super::providers::{OAuthProvider, discord::DiscordOAuth, github::GithubOAuth};

#[derive(Serialize, Deserialize)]
pub struct OAuthState {
    pkce_verifier: String,
    redirect_uri: String,
    existing_user: Option<String>,
}

pub struct Providers {
    pub discord: OAuth<DiscordOAuth>,
    pub github: OAuth<GithubOAuth>,
    login_url: String,
}

impl Providers {
    pub fn new(config: &OAuthConfig, db: Arc<Database>) -> Self {
        let http_client = Providers::build_http_client(&config.user_agent);

        let discord = OAuth::new(config, db.clone(), http_client.clone());
        let github = OAuth::new(config, db.clone(), http_client);

        Self {
            discord,
            github,
            login_url: config.login_url.clone(),
        }
    }

    pub fn login_url(&self) -> &str {
        &self.login_url
    }

    fn build_http_client(user_agent: &str) -> reqwest::Client {
        reqwest::ClientBuilder::new()
            .user_agent(user_agent)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("")
    }
}

pub struct OAuth<T: OAuthProvider> {
    provider: T,
    pkce_cipher: PkceCipher,
    login_url: String,
    db: Arc<Database>,
}

impl<T: OAuthProvider> OAuth<T> {
    pub fn new(config: &OAuthConfig, db: Arc<Database>, http_client: reqwest::Client) -> Self {
        let provider = T::new(config, http_client);

        let pkce_cipher = PkceCipher::new(&config.pkce_secret);
        Self {
            provider,
            pkce_cipher,
            login_url: config.login_url.clone(),
            db,
        }
    }

    fn state_key(&self, csrf: &str) -> String {
        format!("oauth:{}:{}", self.provider.key(), csrf)
    }

    pub async fn auth_url(
        &self,
        redirect_uri: String,
        existing_user: Option<String>,
    ) -> Result<Url, FoundError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let encrypted_pkce_verifier = self.pkce_cipher.encrypt(pkce_verifier.secret().as_bytes());

        let csrf_token = CsrfToken::new_random();

        let state = OAuthState {
            pkce_verifier: encrypted_pkce_verifier,
            redirect_uri,
            existing_user,
        };
        let state_key = self.state_key(csrf_token.secret());

        // TODO errors need to include an actual error type
        self.db
            .redis
            .clone()
            .set_ex::<_, _, ()>(
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
    ) -> Result<(String, String, Option<String>), FoundError> {
        let state_key = self.state_key(&state);

        let state: String = self
            .db
            .redis
            .clone()
            .get_del(&state_key)
            .await
            .map_err(|_| FoundError::new(&self.login_url, "err in state".to_string()))?;

        let oauth_state: OAuthState =
            serde_json::from_str(&state).expect("Failed to parse OAuthState");

        let decrypted_verifier =
            String::from_utf8(self.pkce_cipher.decrypt(&oauth_state.pkce_verifier))
                .expect("Failed to decrypt verifier");

        // TODO error needs to include actual error type
        let access = self
            .provider
            .client()
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(decrypted_verifier))
            .request_async(self.provider.http_client())
            .await
            .map_err(|_| FoundError::new(&self.login_url, "err in exchange".to_string()))?;

        let id = self.provider.callback(&access).await?;

        self.provider.revoke(access, &id).await;

        Ok((id, oauth_state.redirect_uri, oauth_state.existing_user))
    }
}
