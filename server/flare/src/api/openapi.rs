use utoipa::OpenApi;
use utoipa::openapi::security::{ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};

use crate::api::api_params;
use crate::api::routes;
use crate::auth::jwt::{self, REFRESH_TOKEN};

#[derive(OpenApi)]
#[openapi(
    info(title = "flare API",),
    paths(
        routes::auth_ping,
        routes::add_group,
        routes::add_group_user,
        routes::add_image,
        routes::add_poll,
        routes::add_poll_to_group,
        routes::edit_group,
        routes::edit_poll,
        routes::fetch_group,
        routes::fetch_image,
        routes::fetch_poll,
        routes::_fetch_polls,
        routes::fetch_polls,
        routes::fetch_results,
        routes::fetch_vote,
        routes::fetch_voting_image,
        routes::fetch_voting_poll,
        routes::fetch_voting_results,
        routes::join_group,
        routes::leave_group,
        routes::logout,
        routes::oauth_login,
        routes::oauth_callback,
        routes::oauth_unlink,
        routes::ping,
        routes::refresh,
        routes::remove_group,
        routes::remove_group_user,
        routes::remove_image,
        routes::remove_poll,
        routes::remove_user,
        routes::user_info,
        routes::vote,
    ),
    components(
        schemas(
            api_params::AddGroup,
            api_params::AddImage,
            api_params::AddPoll,
            api_params::EditGroup,
            api_params::EditPoll,
            api_params::FetchGroup,
            api_params::FetchPoll,
            api_params::FetchPolls,
            api_params::FetchPollSort,
            api_params::FetchResults,
            api_params::FetchVote,
            api_params::FetchVoteResults,
            api_params::FileName,
            api_params::IdString,
            api_params::Member,
            api_params::PaginatedPoll,
            api_params::PublishResults,
            sea_entity::sea_orm_active_enums::OauthProvider,
            api_params::TokenResponse,
            api_params::UpdatedPoll,
            api_params::UploadedImage,
            api_params::UserInfo,
            api_params::Vote,
            jwt::AccessClaims,
        )
    ),
    modifiers(&AddBearerScheme, &AddCookieScheme)
)]
pub struct ApiDoc;

struct AddBearerScheme;

impl utoipa::Modify for AddBearerScheme {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "ac-admin",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some("Grants admin permissions."))
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components.add_security_scheme(
                "ac-manage-polls",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some("Grants the ability to manage polls."))
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components.add_security_scheme(
                "ac-manage-groups",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some("Grants the ability to manage groups."))
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            components.add_security_scheme(
                "ac-base",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some(
                            "Base authentication level. If you are authenticated, you have this.",
                        ))
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

struct AddCookieScheme;

impl utoipa::Modify for AddCookieScheme {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "ac-refresh",
                SecurityScheme::ApiKey(utoipa::openapi::security::ApiKey::Cookie(
                    ApiKeyValue::with_description(
                        REFRESH_TOKEN,
                        "Your refresh cookie. Only used for acquiring a new access token.",
                    ),
                )),
            );
        }
    }
}
