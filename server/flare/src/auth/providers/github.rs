use oauth2::{
    AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, TokenResponse,
    TokenUrl, basic::BasicClient, url::Url,
};
use secstr::SecUtf8;
use serde_json::json;
use tracing::warn;

use crate::{api::error::FoundError, config::OAuthConfig};

use super::{AccessToken, OAuthClient, OAuthProvider};

#[derive(serde::Deserialize)]
struct UserResponse {
    id: i64,
}

pub struct GithubOAuth {
    http_client: reqwest::Client,
    client: OAuthClient,
    client_secret: SecUtf8,
    client_id: SecUtf8,
    login_url: String,
}

impl OAuthProvider for GithubOAuth {
    fn new(config: &OAuthConfig, http_client: reqwest::Client) -> Self {
        let client = BasicClient::new(ClientId::new(
            config.github.client_id.unsecure().to_string(),
        ))
        .set_client_secret(ClientSecret::new(
            config.github.client_secret.unsecure().to_string(),
        ))
        .set_auth_type(oauth2::AuthType::BasicAuth)
        .set_auth_uri(AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap())
        .set_token_uri(
            TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap(),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/oauth/github/callback", config.api_base)).unwrap(),
        )
        .set_revocation_url_option(None);

        Self {
            http_client,
            client,
            client_id: config.github.client_id.clone(),
            client_secret: config.github.client_secret.clone(),
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

    fn auth_url(&self, csrf: CsrfToken, _: PkceCodeChallenge) -> Url {
        // GitHub doesn't support PKCE
        let (url, _) = self.client.authorize_url(|| csrf).url();
        url
    }

    async fn callback(&self, access: &AccessToken) -> Result<String, FoundError> {
        // TODO error needs to include actual error type
        let response = &self
            .http_client
            .get("https://api.github.com/user")
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(access.access_token().secret())
            .send()
            .await
            .map_err(|_| FoundError::new(&self.login_url, "err fetching user".to_string()))?
            .json::<UserResponse>()
            .await
            .map_err(|_| FoundError::new(&self.login_url, "err parsing ident".to_string()))?;

        Ok(response.id.to_string())
    }

    async fn revoke(&self, access: AccessToken, id: &str) {
        // it would be boring to do what an RFC says, so GitHub decided to be extra and use DELETE instead of POST

        async fn revoke_token(
            client_id: &SecUtf8,
            client_secret: &SecUtf8,
            token: &str,
            client: &reqwest::Client,
        ) -> Result<reqwest::Response, reqwest::Error> {
            client
                .delete(format!(
                    "https://api.github.com/applications/{}/token",
                    client_id.unsecure()
                ))
                .basic_auth(client_id.unsecure(), Some(client_secret.unsecure()))
                .body(json!({ "access_token": token }).to_string())
                .send()
                .await
        }

        if revoke_token(
            &self.client_id,
            &self.client_secret,
            access.access_token().secret(),
            &self.http_client,
        )
        .await
        .is_err()
        {
            warn!(
                "{}",
                format!("Failed to revoke {} access token for {}", self.key(), id)
            );
        }

        if access.refresh_token().is_some()
            && revoke_token(
                &self.client_id,
                &self.client_secret,
                access.refresh_token().unwrap().secret(),
                &self.http_client,
            )
            .await
            .is_err()
        {
            warn!(
                "{}",
                format!("Failed to revoke {} refresh token for {}", self.key(), id)
            );
        }
    }
}
