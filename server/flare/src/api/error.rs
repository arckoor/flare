use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use prisma_client_rust::{
    prisma_errors::query_engine::{RecordNotFound, UniqueKeyViolation},
    QueryError,
};

/// An error for flare REST API.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct RestError {
    msg: String,
    code: StatusCode,
}

impl RestError {
    /// Creates a new flare API REST error.
    pub fn new<S>(code: StatusCode, msg: S) -> Self
    where
        S: Into<String>,
    {
        RestError {
            msg: msg.into(),
            code,
        }
    }

    /// Shorthand for creating a flare API REST error with `BAD_REQUEST` status code.
    pub fn bad_req<S>(msg: S) -> Self
    where
        S: Into<String>,
    {
        RestError::new(StatusCode::BAD_REQUEST, msg)
    }

    /// Shorthand for creating a flare API REST error with `UNAUTHORIZED` status code.
    pub fn unauthorized<S>(msg: S) -> Self
    where
        S: Into<String>,
    {
        RestError::new(StatusCode::UNAUTHORIZED, msg)
    }

    /// Shorthand for creating a flare API REST error with `FORBIDDEN` status code.
    pub fn forbidden<S>(msg: S) -> Self
    where
        S: Into<String>,
    {
        RestError::new(StatusCode::FORBIDDEN, msg)
    }

    /// Shorthand for creating a flare API REST error with `NOT_FOUND` status code.
    pub fn not_found<S>(msg: S) -> Self
    where
        S: Into<String>,
    {
        RestError::new(StatusCode::NOT_FOUND, msg)
    }

    /// Shorthand for creating a flare API REST error with `CONFLICT` status code.
    pub fn conflict<S>(msg: S) -> Self
    where
        S: Into<String>,
    {
        RestError::new(StatusCode::CONFLICT, msg)
    }

    /// Shorthand for creating a flare API REST error with `INTERNAL_SERVER_ERROR` status code.
    pub fn internal<S>(msg: S) -> Self
    where
        S: Into<String>,
    {
        RestError::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}

impl std::fmt::Display for RestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for RestError {}

impl IntoResponse for RestError {
    fn into_response(self) -> Response {
        (self.code, self.msg).into_response()
    }
}

impl From<QueryError> for RestError {
    fn from(error: QueryError) -> Self {
        match error {
            e if e.is_prisma_error::<RecordNotFound>() => RestError::not_found("Record not found"),
            e if e.is_prisma_error::<UniqueKeyViolation>() => {
                RestError::conflict("Record already exists")
            }
            _ => RestError::internal("Error while processing request".to_string()),
        }
    }
}
