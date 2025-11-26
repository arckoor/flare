use sea_orm::FromJsonQueryResult;
use serde::{Deserialize, Serialize};

#[derive(
    Serialize, Deserialize, Clone, Debug, PartialEq, Eq, FromJsonQueryResult, utoipa::ToSchema,
)]
pub enum RecurrenceRule {
    Weekly { interval_weeks: u32 },
    DaysBeforeEndOfMonth { days: u32 },
}
