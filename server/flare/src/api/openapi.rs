use sea_entity;
use utoipa::OpenApi;
use utoipa::openapi::security::{ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};

use crate::api::{api_params, routes};
use crate::auth::jwt::{self, REFRESH_TOKEN};

#[derive(OpenApi)]
#[openapi(
    info(title = "flare API",),
    paths(
        routes::auth_ping,
        routes::add_image,
        routes::fetch_image,
        routes::ping,
        routes::remove_image,
        routes::admin::run_task,
        routes::auth::logout,
        routes::auth::oauth_login,
        routes::auth::oauth_callback,
        routes::auth::oauth_unlink,
        routes::auth::refresh,
        routes::auth::remove_user,
        routes::auth::user_info,
        routes::groups::add_group,
        routes::groups::add_group_user,
        routes::groups::edit_group,
        routes::groups::fetch_group,
        routes::groups::join_group,
        routes::groups::leave_group,
        routes::groups::remove_group,
        routes::groups::remove_group_user,
        routes::polls::add_poll,
        routes::polls::add_poll_to_group,
        routes::polls::add_scheduled_poll,
        routes::polls::approve_scheduled_poll_submission,
        routes::polls::edit_poll,
        routes::polls::edit_scheduled_poll,
        routes::polls::edit_scheduled_poll_submission,
        routes::polls::fetch_poll,
        routes::polls::_fetch_polls,
        routes::polls::fetch_polls,
        routes::polls::fetch_results,
        routes::polls::fetch_scheduled_poll,
        routes::polls::_fetch_scheduled_polls,
        routes::polls::fetch_scheduled_polls,
        routes::polls::fetch_scheduled_poll_submission,
        routes::polls::fetch_scheduled_poll_submissions,
        routes::polls::publish_results,
        routes::polls::remove_poll,
        routes::polls::remove_scheduled_poll,
        routes::voting::fetch_vote,
        routes::voting::fetch_voting_image,
        routes::voting::fetch_voting_poll,
        routes::voting::fetch_voting_results,
        routes::voting::vote,
    ),
    components(
        schemas(
            api_params::AddGroup,
            api_params::AddImage,
            api_params::AddPoll,
            api_params::AddScheduledPoll,
            api_params::ApproveScheduledPollSubmission,
            api_params::EditGroup,
            api_params::EditPoll,
            api_params::EditScheduledPoll,
            api_params::EditScheduledPollSubmission,
            api_params::FetchGroup,
            api_params::FetchPoll,
            api_params::FetchPolls,
            api_params::FetchPollSort,
            api_params::FetchResults,
            api_params::FetchScheduledPoll,
            api_params::FetchScheduledPolls,
            api_params::FetchScheduledPollSort,
            api_params::FetchScheduledPollSubmission,
            api_params::FetchScheduledPollSubmissions,
            api_params::FetchVote,
            api_params::FetchVoteResults,
            api_params::FileName,
            api_params::IdString,
            api_params::Member,
            api_params::PaginatedPoll,
            api_params::PublishResults,
            api_params::ScheduledPollSubmission,
            api_params::Task,
            api_params::TokenResponse,
            api_params::UpdatedPoll,
            api_params::UploadedImage,
            api_params::UserInfo,
            api_params::Vote,
            jwt::AccessClaims,
            sea_entity::api_params::RecurrenceRule,
            sea_entity::sea_orm_active_enums::OauthProvider,
        )
    ),
    modifiers(&AddBearerScheme, &AddCookieScheme)
)]
pub struct ApiDoc;

struct AddBearerScheme;

impl utoipa::Modify for AddBearerScheme {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let security_schemes = [
            ("ac-admin", "Grants admin permissions."),
            (
                "ac-manage-scheduled-polls",
                "Grants the ability to manage scheduled polls.",
            ),
            (
                "ac-approve-scheduled-poll-submission",
                "Grants the ability to approve submissions for scheduled polls",
            ),
            ("ac-manage-polls", "Grants the ability to manage polls."),
            ("ac-manage-groups", "Grants the ability to manage groups."),
            (
                "ac-base",
                "Base authentication level. If you are authenticated, you have this.",
            ),
        ];

        if let Some(components) = openapi.components.as_mut() {
            for (name, description) in security_schemes {
                components.add_security_scheme(
                    name,
                    SecurityScheme::Http(
                        HttpBuilder::new()
                            .scheme(HttpAuthScheme::Bearer)
                            .description(Some(description))
                            .bearer_format("JWT")
                            .build(),
                    ),
                );
            }
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
