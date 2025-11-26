use secstr::{SecStr, SecUtf8};
use serde::{Deserialize, Serializer};

pub fn deserialize_secstr_hex<'de, D>(deserializer: D) -> Result<SecStr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let bytes = botan::hex_decode(&s).map_err(serde::de::Error::custom)?;
    Ok(SecStr::from(bytes))
}

pub fn deserialize_secutf8<'de, D>(deserializer: D) -> Result<SecUtf8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Ok(SecUtf8::from(s))
}

pub fn serialize_secutf8<S>(value: &SecUtf8, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.unsecure())
}
