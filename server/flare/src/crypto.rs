use secstr::{SecStr, SecUtf8};
use serde::Deserialize;

pub fn deserialize_secstr<'de, D>(deserializer: D) -> Result<SecStr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Ok(SecStr::from(s))
}

pub fn deserialize_secutf8<'de, D>(deserializer: D) -> Result<SecUtf8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Ok(SecUtf8::from(s))
}
