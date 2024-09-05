use oauth2::{
    basic::BasicClient, url::Url, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RevocationUrl, Scope, TokenResponse,
    TokenUrl,
};
use secstr::SecUtf8;

use crate::api::error::FoundError;

use super::oauth::{OAuthClient, OAuthProvider};

#[derive(serde::Deserialize)]
pub struct IdentifyResponse {
    pub id: String,
    pub username: String,
}

pub struct DiscordOAuth {
    client: OAuthClient,
    login_url: String,
}

impl OAuthProvider for DiscordOAuth {
    fn new(client_id: &SecUtf8, client_secret: &SecUtf8, login_url: String) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id.unsecure().to_string()),
            Some(ClientSecret::new(client_secret.unsecure().to_string())),
            AuthUrl::new("https://discord.com/oauth2/authorize".to_string())
                .expect("Failed to create AuthUrl"),
            Some(TokenUrl::new("https://discord.com/api/oauth2/token".to_string()).unwrap()),
        )
        .set_redirect_uri(
            RedirectUrl::new("https://localhost/api/oauth/discord/callback".to_string()).unwrap(),
        )
        .set_revocation_uri(
            RevocationUrl::new("https://discord.com/api/oauth2/token/revoke".to_string()).unwrap(),
        );

        Self { client, login_url }
    }

    fn auth_url(&self, csrf: CsrfToken, challenge: PkceCodeChallenge) -> Url {
        let (url, _) = self
            .client
            .authorize_url(|| csrf)
            .add_scope(Scope::new("identify".to_string()))
            .set_pkce_challenge(challenge)
            .url();

        url
    }

    async fn callback(&self, code: String, verifier: String) -> Result<(i64, String), FoundError> {
        let access = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(verifier))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|_| FoundError::new(&self.login_url, "".to_string()))?;

        // TODO error needs to include actual error type
        let response = reqwest::Client::new()
            .get("https://discord.com/api/users/@me")
            .bearer_auth(access.access_token().secret())
            .send()
            .await
            .map_err(|_| FoundError::new(&self.login_url, "".to_string()))?
            .json::<IdentifyResponse>()
            .await
            .map_err(|_| FoundError::new(&self.login_url, "".to_string()))?;

        // TODO fail gracefully, but log it!
        self.client
            .revoke_token(access.access_token().into())
            .map_err(|_| FoundError::new(&self.login_url, "".to_string()))?;

        let id = response.id.parse().expect("User id is always a number");
        let username = response.username.clone();

        Ok((id, username))
    }
}
