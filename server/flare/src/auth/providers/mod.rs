pub mod discord;
pub mod github;

use oauth2::{CsrfToken, PkceCodeChallenge, TokenResponse, url::Url};
use tracing::warn;

use crate::{api::error::FoundError, config::OAuthConfig};

pub type OAuthClient = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
    oauth2::StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointMaybeSet,
    oauth2::EndpointSet,
>;

pub type AccessToken =
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>;

pub trait OAuthProvider: Send + Sync {
    fn new(config: &OAuthConfig, http_client: reqwest::Client) -> Self;
    fn client(&self) -> &OAuthClient;
    fn http_client(&self) -> &reqwest::Client;
    fn identifier(&self) -> &'static str;
    fn auth_url(&self, csrf: CsrfToken, challenge: PkceCodeChallenge) -> Url;
    fn callback(
        &self,
        access: &AccessToken,
    ) -> impl std::future::Future<Output = Result<String, FoundError>> + Send;
    fn revoke(
        &self,
        access: AccessToken,
        id: &str,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            let http_client = self.http_client();

            if access.refresh_token().is_some()
                && self
                    .client()
                    .revoke_token(access.refresh_token().unwrap().into())
                    .expect("Revocation url must be provided")
                    .request_async(http_client)
                    .await
                    .is_err()
            {
                warn!(
                    "{}",
                    format!(
                        "Failed to revoke {} refresh token for {}",
                        self.identifier(),
                        id
                    )
                );
            }

            if self
                .client()
                .revoke_token(access.access_token().into())
                .expect("Revocation url must be provided")
                .request_async(http_client)
                .await
                .is_err()
            {
                warn!(
                    "{}",
                    format!(
                        "Failed to revoke {} access token for {}",
                        self.identifier(),
                        id
                    )
                );
            }
        }
    }
}
