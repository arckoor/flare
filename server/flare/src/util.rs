use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::api::error::RestError;

pub fn now() -> Result<Duration, RestError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RestError::internal("Failed to get system time"))
}
