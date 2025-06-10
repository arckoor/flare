use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const ONE_MINUTE: f64 = 60.0;
pub const ONE_HOUR: f64 = ONE_MINUTE * 60.0;
pub const ONE_DAY: f64 = ONE_HOUR * 24.0;
pub const ONE_WEEK: f64 = ONE_DAY * 7.0;
pub const ONE_MONTH: f64 = ONE_DAY * 30.0;
pub const ONE_YEAR: f64 = ONE_DAY * 365.0;

pub fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Getting the time must work")
}

pub fn minutes(n: u64) -> Duration {
    Duration::from_secs((ONE_MINUTE as u64) * n)
}
