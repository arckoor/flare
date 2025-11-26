use std::time::Duration;
#[cfg(not(feature = "sim"))]
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Datelike, NaiveDate, TimeDelta, TimeZone, Utc};
use sea_entity::api_params::RecurrenceRule;

use crate::api::error::RestError;

pub const ONE_MINUTE: f64 = 60.0;
pub const ONE_HOUR: f64 = ONE_MINUTE * 60.0;
pub const ONE_DAY: f64 = ONE_HOUR * 24.0;
pub const ONE_WEEK: f64 = ONE_DAY * 7.0;
pub const ONE_MONTH: f64 = ONE_DAY * 30.0;
pub const ONE_YEAR: f64 = ONE_DAY * 365.0;

#[cfg(feature = "sim")]
pub mod sim_time {
    use std::{
        sync::{LazyLock, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    static PROCESS_CLOCK: LazyLock<SimClock> = LazyLock::new(|| SimClock {
        offset: Mutex::new(0.0),
    });

    pub struct SimClock {
        offset: Mutex<f64>,
    }

    impl SimClock {
        pub fn now() -> Duration {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .checked_add(Duration::from_secs_f64(
                    *PROCESS_CLOCK.offset.lock().unwrap(),
                ))
                .unwrap()
        }

        pub fn add_offset(offset: f64) {
            *PROCESS_CLOCK.offset.lock().unwrap() += offset;
        }
    }
}

#[cfg(feature = "sim")]
pub fn now() -> Duration {
    sim_time::SimClock::now()
}

#[cfg(not(feature = "sim"))]
pub fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Getting the time must work")
}

pub fn minutes(n: u64) -> Duration {
    Duration::from_secs((ONE_MINUTE as u64) * n)
}

fn f64_to_datetime(ts: f64) -> Option<DateTime<Utc>> {
    // todo it might be smarter to just ignore the subsecs so we don't run into weird drift issues
    let secs = ts.trunc() as i64;
    let nanos = (ts.fract() * 1e9).round() as u32;
    DateTime::from_timestamp(secs, nanos)
}

fn datetime_to_f64(dt: DateTime<Utc>) -> f64 {
    dt.timestamp() as f64 + (dt.timestamp_subsec_nanos() as f64 / 1e9)
}

pub fn next_run(start_time: f64, recurrence: &Option<RecurrenceRule>) -> Result<f64, RestError> {
    let base_dt =
        f64_to_datetime(start_time).ok_or_else(|| RestError::internal("Could not convert time"))?;

    match recurrence {
        None => Ok(start_time),

        Some(RecurrenceRule::Weekly { interval_weeks }) => {
            let next_date = base_dt + TimeDelta::weeks(*interval_weeks as i64);
            Ok(datetime_to_f64(next_date))
        }

        Some(RecurrenceRule::DaysBeforeEndOfMonth { days }) => {
            let time = base_dt.time();
            let mut year = base_dt.year();
            let mut month = base_dt.month();

            for _ in 0..2 {
                let last_day = (28..=31)
                    .rev()
                    .find_map(|day| NaiveDate::from_ymd_opt(year, month, day))
                    .ok_or_else(|| RestError::internal("Could not create start date"))?;
                let target_date = last_day
                    .checked_sub_days(chrono::Days::new(*days as u64))
                    .ok_or_else(|| RestError::internal("Could not create target date"))?;
                let target_dt = Utc.from_utc_datetime(&target_date.and_time(time));
                if target_dt > base_dt {
                    return Ok(datetime_to_f64(target_dt));
                }
                month += 1;
                if month > 12 {
                    year += 1;
                    month = 1;
                }
            }

            Err(RestError::internal("Could not compute next run date"))
        }
    }
}

pub fn find_next_run(
    now: f64,
    start_time: f64,
    cutoff: f64,
    recurrence: &Option<RecurrenceRule>,
) -> Result<f64, RestError> {
    if recurrence.is_none() && now > (start_time - cutoff) {
        return Err(RestError::bad_req(
            "Submission window for this poll is closed",
        ));
    }
    let mut current = start_time;
    while now > (current - cutoff) {
        let previous = current;
        current = next_run(current, recurrence)?;
        if previous >= current {
            return Err(RestError::internal(
                "Could not find a suitable submission date",
            ));
        }
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion() {
        for ts in [1750089600.123456, 1750694400.99999, 1751299200.010101] {
            assert_eq!(ts, datetime_to_f64(f64_to_datetime(ts).unwrap()));
        }
    }

    #[test]
    fn test_recurrence_weekly() {
        // one week
        assert_eq!(
            next_run(
                1750089600.0,
                &Some(RecurrenceRule::Weekly { interval_weeks: 1 })
            )
            .unwrap(),
            1750694400.0
        );

        // two weeks
        assert_eq!(
            next_run(
                1750089600.0,
                &Some(RecurrenceRule::Weekly { interval_weeks: 2 })
            )
            .unwrap(),
            1751299200.0
        );

        // two times one week
        assert_eq!(
            next_run(
                next_run(
                    1750089600.0,
                    &Some(RecurrenceRule::Weekly { interval_weeks: 1 })
                )
                .unwrap(),
                &Some(RecurrenceRule::Weekly { interval_weeks: 1 }),
            )
            .unwrap(),
            1751299200.0
        );

        assert_eq!(
            next_run(
                1750089600.0,
                &Some(RecurrenceRule::Weekly { interval_weeks: 10 })
            )
            .unwrap(),
            1756137600.0
        );
    }

    #[test]
    fn test_recurrence_n_before_end_of_month() {
        // stay in the current month
        assert_eq!(
            next_run(
                1750089600.0,
                &Some(RecurrenceRule::DaysBeforeEndOfMonth { days: 1 })
            )
            .unwrap(),
            1751212800.0
        );

        assert_eq!(
            next_run(
                1750089600.0,
                &Some(RecurrenceRule::DaysBeforeEndOfMonth { days: 5 })
            )
            .unwrap(),
            1750867200.0
        );

        // overflows to next month
        assert_eq!(
            next_run(
                1751040000.0,
                &Some(RecurrenceRule::DaysBeforeEndOfMonth { days: 5 })
            )
            .unwrap(),
            1753545600.0
        );

        // overflow to next year
        assert_eq!(
            next_run(
                1766583222.0,
                &Some(RecurrenceRule::DaysBeforeEndOfMonth { days: 8 })
            )
            .unwrap(),
            1769175222.0
        );
    }

    #[test]
    fn test_find_next_run() {
        assert_eq!(
            1750089600.0,
            find_next_run(1750089599.0, 1750089600.0, 0.0, &None).unwrap()
        );

        assert_eq!(
            1750694400.0,
            find_next_run(
                1750348800.0,
                1750089600.0,
                0.0,
                &Some(RecurrenceRule::Weekly { interval_weeks: 1 }),
            )
            .unwrap()
        );

        assert_eq!(
            1750694400.0,
            find_next_run(
                1750608000.0,
                1750089600.0,
                86400.0,
                &Some(RecurrenceRule::Weekly { interval_weeks: 1 }),
            )
            .unwrap()
        );

        assert_eq!(
            1751299200.0,
            find_next_run(
                1750608001.0,
                1750089600.0,
                86400.0,
                &Some(RecurrenceRule::Weekly { interval_weeks: 1 }),
            )
            .unwrap()
        );

        assert_eq!(
            1751904000.0,
            find_next_run(
                1751385600.0,
                1750089600.0,
                0.0,
                &Some(RecurrenceRule::Weekly { interval_weeks: 1 }),
            )
            .unwrap()
        );

        assert_eq!(
            1750867200.0,
            find_next_run(
                1750348800.0,
                1750089600.0,
                0.0,
                &Some(RecurrenceRule::DaysBeforeEndOfMonth { days: 5 }),
            )
            .unwrap()
        );

        assert_eq!(
            1756224000.0,
            find_next_run(
                1754789025.0,
                1750089600.0,
                0.0,
                &Some(RecurrenceRule::DaysBeforeEndOfMonth { days: 5 }),
            )
            .unwrap()
        );
    }
}
