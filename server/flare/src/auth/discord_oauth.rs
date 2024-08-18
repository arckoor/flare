use std::sync::Arc;

use oauth2::{
    basic::{self, BasicClient},
    url::Url,
    AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use redis::AsyncCommands;
use secstr::SecStr;

use crate::{api::error::RestError, db::Database};

#[derive(serde::Deserialize)]
pub struct IdentifyResponse {
    pub id: String,
    pub username: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct OAuthState {
    csrf_token: String,
    pkce_verifier: String,
    redirect_uri: String,
}

type DiscordClient = Client<
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

pub struct DiscordOAuth {
    client: DiscordClient,
    db: Arc<Database>,
}

impl DiscordOAuth {
    pub fn new(client_id: SecStr, client_secret: SecStr, db: Arc<Database>) -> Self {
        let client = BasicClient::new(
            ClientId::new(
                String::from_utf8(client_id.unsecure().to_vec())
                    .expect("ClientID is always valid UTF-8"),
            ),
            Some(ClientSecret::new(
                String::from_utf8(client_secret.unsecure().to_vec())
                    .expect("ClientSecret is always valid UTF-8"),
            )),
            AuthUrl::new("https://discord.com/api/oauth2/authorize".to_string())
                .expect("Failed to create AuthUrl"),
            Some(
                TokenUrl::new("https://discord.com/api/oauth2/token".to_string())
                    .expect("Failed to create TokenUrl"),
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new("http://localhost:8080/api/oauth/discord/callback".to_string())
                .expect("Failed to create RedirectUrl"),
        );

        Self { client, db }
    }

    pub async fn auth_url(&self, redirect_uri: String) -> Result<(Url, CsrfToken), RestError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let csrf_token = CsrfToken::new_random();

        let state = OAuthState {
            csrf_token: csrf_token.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
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

        Ok(self
            .client
            .authorize_url(|| csrf_token.clone())
            .add_scope(Scope::new("identify".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url())
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
            .get(&state_key)
            .await
            .map_err(|_| RestError::internal("Failed to get state"))?;

        let oauth_state: OAuthState =
            serde_json::from_str(&state).expect("Failed to parse OAuthState");

        // TODO
        let decrypted_verifier = oauth_state.pkce_verifier;

        let access = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(decrypted_verifier))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|_| RestError::internal("Failed to exchange code"))?;

        let response = reqwest::Client::new()
            .get("https://discord.com/api/users/@me")
            .bearer_auth(access.access_token().secret())
            .send()
            .await
            .map_err(|_| RestError::internal("Failed to get user info"))?
            .json::<IdentifyResponse>()
            .await
            .map_err(|_| RestError::internal("Failed to parse user info"))?;

        let id = response.id.parse().expect("User id is always a number");
        let username = response.username.clone();

        Ok((id, username, oauth_state.redirect_uri))
    }
}
