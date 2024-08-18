use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::OpenApi;

use crate::api::api_params;
use crate::api::routes;

#[derive(OpenApi)]
#[openapi(
    info(title = "flare API",),
    paths(routes::login, routes::test_protected_route),
    components(schemas(api_params::TokenResponse, api_params::LoginInfo)),
    modifiers(
        &AddBearerScheme,
    )
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
            )
        }
    }
}
