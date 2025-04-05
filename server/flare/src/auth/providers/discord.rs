use oauth2::{
    AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, RevocationUrl,
    Scope, TokenResponse, TokenUrl, basic::BasicClient, url::Url,
};

use crate::{api::error::FoundError, config::OAuthConfig};

use super::{AccessToken, OAuthClient, OAuthProvider};

#[derive(serde::Deserialize)]
struct IdentifyResponse {
    id: String,
}

pub struct DiscordOAuth {
    http_client: reqwest::Client,
    client: OAuthClient,
    login_url: String,
}

impl OAuthProvider for DiscordOAuth {
    fn new(config: &OAuthConfig, http_client: reqwest::Client) -> Self {
        let client = BasicClient::new(ClientId::new(
            config.discord.client_id.unsecure().to_string(),
        ))
        .set_client_secret(ClientSecret::new(
            config.discord.client_secret.unsecure().to_string(),
        ))
        .set_auth_type(oauth2::AuthType::BasicAuth)
        .set_auth_uri(AuthUrl::new("https://discord.com/oauth2/authorize".to_string()).unwrap())
        .set_token_uri(TokenUrl::new("https://discord.com/api/oauth2/token".to_string()).unwrap())
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/oauth/discord/callback", config.api_base)).unwrap(),
        )
        .set_revocation_url_option(Some(
            RevocationUrl::new("https://discord.com/api/oauth2/token/revoke".to_string()).unwrap(),
        ));

        Self {
            http_client,
            client,
            login_url: config.login_url.clone(),
        }
    }

    fn client(&self) -> &OAuthClient {
        &self.client
    }

    fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    fn key(&self) -> &'static str {
        "discord"
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

    async fn callback(&self, access: &AccessToken) -> Result<String, FoundError> {
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

        Ok(response.id)
    }
}
