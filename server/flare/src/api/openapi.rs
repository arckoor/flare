use utoipa::OpenApi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

use crate::api::api_params;
use crate::api::routes;

#[derive(OpenApi)]
#[openapi(
    info(title = "flare API",),
    paths(routes::ping, routes::auth_ping, routes::add_image),
    components(schemas(api_params::TokenResponse, api_params::UploadedImage, api_params::AddImage, api_params::AddPoll)),
    modifiers(&AddBearerScheme)
)]
pub struct ApiDoc;

struct AddBearerScheme;

impl utoipa::Modify for AddBearerScheme {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer-auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}
