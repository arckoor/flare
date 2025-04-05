use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hyper::header;
use sea_orm::{DbErr, SqlErr, TransactionError};
use tracing::{error, info};

/// An error for flare REST API.
#[derive(Debug)]
pub struct RestError {
    code: StatusCode,
    msg: String,
}

impl RestError {
    /// Creates a new flare API REST error.
    pub fn new<S>(code: StatusCode, msg: S) -> Self
    where
        S: Into<String> + std::fmt::Display,
    {
        RestError {
            code,
            msg: msg.into(),
        }
    }

    /// Shorthand for creating a flare API REST error with `BAD_REQUEST` status code.
    pub fn bad_req<S>(msg: S) -> Self
    where
        S: Into<String> + std::fmt::Display,
    {
        RestError::new(StatusCode::BAD_REQUEST, msg)
    }

    /// Shorthand for creating a flare API REST error with `UNAUTHORIZED` status code.
    pub fn unauthorized<S>(msg: S) -> Self
    where
        S: Into<String> + std::fmt::Display,
    {
        RestError::new(StatusCode::UNAUTHORIZED, msg)
    }

    /// Shorthand for creating a flare API REST error with `FORBIDDEN` status code.
    pub fn forbidden<S>(msg: S) -> Self
    where
        S: Into<String> + std::fmt::Display,
    {
        RestError::new(StatusCode::FORBIDDEN, msg)
    }

    /// Shorthand for creating a flare API REST error with `NOT_FOUND` status code.
    pub fn not_found<S>(msg: S) -> Self
    where
        S: Into<String> + std::fmt::Display,
    {
        RestError::new(StatusCode::NOT_FOUND, msg)
    }

    /// Shorthand for creating a flare API REST error with `CONFLICT` status code.
    pub fn conflict<S>(msg: S) -> Self
    where
        S: Into<String> + std::fmt::Display,
    {
        RestError::new(StatusCode::CONFLICT, msg)
    }

    /// Shorthand for creating a flare API REST error with `INTERNAL_SERVER_ERROR` status code.
    #[track_caller]
    pub fn internal<S>(msg: S) -> Self
    where
        S: Into<String> + std::fmt::Display,
    {
        error!(
            "internal error at {}: {}",
            std::panic::Location::caller(),
            msg
        );
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

impl From<DbErr> for RestError {
    #[track_caller]
    fn from(error: DbErr) -> Self {
        info!(
            "Database error at {}: {:?}",
            std::panic::Location::caller(),
            error
        );
        if let Some(sql_err) = error.sql_err() {
            if let SqlErr::UniqueConstraintViolation(_) = sql_err {
                return RestError::conflict("Record already exists");
            }
        } else if let DbErr::RecordNotFound(_) = error {
            return RestError::not_found("Record not found");
        }
        RestError::internal("Error while processing request".to_string())
    }
}

impl From<TransactionError<RestError>> for RestError {
    #[track_caller]
    fn from(value: TransactionError<RestError>) -> Self {
        info!(
            "Transaction error at {}: {:?}",
            std::panic::Location::caller(),
            value
        );
        match value {
            TransactionError::Transaction(e) => e,
            _ => RestError::internal("Error while processing request".to_string()),
        }
    }
}

/// An error for flare API that redirects to a location.
#[derive(Debug)]
pub struct FoundError {
    pub location: String,
    pub msg: String,
}

// TODO maybe we should use query string instead of a message, and provide an error_code for the frontend to interpret and inform the user
impl FoundError {
    /// Creates a new flare API found error.
    #[track_caller]
    pub fn new(location: &str, msg: String) -> Self {
        // todo this is logging
        info!(
            "Redirect to: {} from {}",
            msg,
            std::panic::Location::caller()
        );
        FoundError {
            location: location.to_string(),
            msg,
        }
    }
}

impl std::fmt::Display for FoundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "-> {}, {}", self.location, self.msg)
    }
}

impl std::error::Error for FoundError {}

impl IntoResponse for FoundError {
    fn into_response(self) -> Response {
        (
            StatusCode::FOUND,
            [(header::LOCATION, self.location)],
            self.msg,
        )
            .into_response()
    }
}
