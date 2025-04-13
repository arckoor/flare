use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    os::unix::ffi::OsStrExt,
    path::{Component, Path},
    str::FromStr,
};

use secstr::SecUtf8;
use serde::{
    Deserialize, Serialize,
    de::{self, Unexpected},
};

use crate::crypto::{deserialize_secutf8, serialize_secutf8};

use super::error::RestError;

const fn default_page_size() -> u64 {
    20
}

const fn default_page() -> u64 {
    0
}

pub trait PaginatedSort {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum FetchPollSort {
    CreatedAt,
    Title,
    Ends,
}

impl PaginatedSort for FetchPollSort {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Paginator<S: PaginatedSort> {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    #[serde(default)]
    pub asc: bool,
    pub sort_by: Option<S>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg(feature = "sim")]
pub struct LoginInfo {
    pub id: String,
}

// TODO these parameters are super inconsistent, sometimes we return an additional id, sometimes we don't

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct OAuthLogin {
    pub redirect_url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct OAuthCallback {
    pub code: String,
    pub state: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct TokenResponse {
    #[serde(
        deserialize_with = "deserialize_secutf8",
        serialize_with = "serialize_secutf8"
    )]
    #[cfg_attr(feature = "api-doc", schema(value_type = String))]
    /// a JWT access token
    pub access: SecUtf8,
}

// todo https://docs.rs/utoipa/latest/utoipa/attr.path.html#defining-file-uploads
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct AddImage {
    #[cfg_attr(
        feature = "api-doc",
        schema(content_media_type = "application/octet-stream")
    )]
    pub file_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct UploadedImage {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct AddPoll {
    pub title: String,
    pub info: String,
    /// timestamp in seconds (Unix time)
    pub ends: f64,
    pub images: HashSet<String>,
    pub allowed_votes: u32,
    pub group: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct AddedPoll {
    pub id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct PaginatedPoll {
    pub id: String,
    pub title: String,
    pub ends: f64,
    pub votes: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct FetchPolls {
    pub polls: Vec<PaginatedPoll>,
    pub page: u64,
    pub page_count: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct FetchPoll {
    pub id: String,
    pub title: String,
    pub info: String,
    pub ends: f64,
    pub allowed_votes: u32,
    pub votes: u64,
    pub images: HashSet<String>,
    pub aspect_ratios: HashMap<String, String>,
    pub group: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct EditPoll {
    pub title: Option<String>,
    pub info: Option<String>,
    pub ends: Option<f64>,
    pub allowed_votes: Option<u32>,
    pub add_images: Option<HashSet<String>>,
    pub remove_images: Option<HashSet<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FetchResults {
    pub id: String,
    pub ended: bool,
    pub public: bool,
    pub votes: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct PublishResults {
    pub published: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct AddGroup {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct EditGroup {
    pub name: Option<String>,
    pub owner: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct Group {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub members: Vec<Member>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct Member {
    pub id: String,
    // TODO name??
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct FetchVotingPoll {
    pub id: String,
    pub title: String,
    pub info: String,
    pub ends: f64,
    pub allowed_votes: u32,
    pub images: HashSet<String>,
    pub aspect_ratios: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct FetchVote {
    pub created: f64,
    pub votes: HashSet<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct FetchVoteResults {
    pub id: String,
    pub first: String,
    pub second: String,
    pub third: Option<String>,
    pub remaining: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct Vote {
    pub votes: HashSet<String>,
}

#[derive(Serialize, PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "api-doc", derive(utoipa::ToSchema))]
pub struct FileName(pub String);

impl FileName {
    pub fn new<P>(filename: P) -> Result<Self, RestError>
    where
        P: AsRef<Path>,
    {
        let err = Err(RestError::bad_req("Invalid filename".to_string()));

        let components: Vec<Component> = filename.as_ref().components().collect();

        if components.len() != 1 {
            return err;
        }

        let component = components
            .first()
            .expect("There must be exactly one component");

        if !matches!(component, Component::Normal(_)) {
            return err;
        }

        if component
            .as_os_str()
            .as_bytes()
            .iter()
            .any(|c| !c.is_ascii_alphanumeric() && c != &b'.')
        {
            return err;
        }

        let normalized = component.as_os_str().to_str();

        let filename = match normalized {
            Some(s) => s.to_owned(),
            None => return err,
        };

        Ok(Self(filename))
    }
}

impl AsRef<Path> for FileName {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl Display for FileName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for FileName {
    type Err = RestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FileName::new(s)
    }
}

impl<'de> Deserialize<'de> for FileName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        s.parse()
            .map_err(|_| de::Error::invalid_value(Unexpected::Str(&s), &"valid file name"))
    }
}

#[cfg(test)]
mod tests {

    use super::FileName;

    #[test]
    fn test_filename() {
        assert!(FileName::new("test").is_ok());
        assert!(FileName::new("test.txt").is_ok());
        assert!("test".parse::<FileName>().is_ok());
        assert!("test.txt".parse::<FileName>().is_ok());
        assert!("foo/test.txt".parse::<FileName>().is_err());
        assert!("".parse::<FileName>().is_err());
        assert!("test.txt?".parse::<FileName>().is_err());
        assert!("../../test.txt".parse::<FileName>().is_err());
        assert!("test.txt\\".parse::<FileName>().is_err());
        assert!(".".parse::<FileName>().is_err());
        assert!("..".parse::<FileName>().is_err());
        assert!("/test".parse::<FileName>().is_err());

        // this should be normalised
        assert_eq!(
            "test.txt/".parse::<FileName>().unwrap(),
            "test.txt".parse().unwrap()
        );
    }
}
