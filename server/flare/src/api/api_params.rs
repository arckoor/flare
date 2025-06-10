use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    os::unix::ffi::OsStrExt,
    path::{Component, Path},
    str::FromStr,
};

use sea_entity::sea_orm_active_enums::OauthProvider;
use secstr::SecUtf8;
use serde::{
    Deserialize, Serialize,
    de::{self, Unexpected},
};

use crate::{
    api::error::RestError,
    crypto::{deserialize_secutf8, serialize_secutf8},
};

const fn default_page_size() -> u64 {
    20
}

const fn default_page() -> u64 {
    0
}

pub trait PaginatedSort: utoipa::ToSchema {}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
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

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OAuthLogin {
    pub redirect_url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OAuthCallback {
    pub code: String,
    pub state: String,
}

#[derive(Serialize, Deserialize, Debug, utoipa::ToSchema)]
pub struct TokenResponse {
    #[serde(
        deserialize_with = "deserialize_secutf8",
        serialize_with = "serialize_secutf8"
    )]
    #[schema(value_type = String)]
    /// a JWT access token
    pub access: SecUtf8,
}

#[derive(Serialize, Deserialize, Debug, utoipa::ToSchema)]
pub struct UserInfo {
    /// map from an oauth provider to the oauth id
    pub logins: HashMap<OauthProvider, String>,
}

#[derive(utoipa::ToSchema)]
pub struct AddImage {
    #[schema(format = Binary, content_media_type = "application/octet-stream")]
    pub file_bytes: String,
}

#[derive(Serialize, Deserialize, Debug, utoipa::ToSchema)]
pub struct UploadedImage {
    /// The name assigned to the image
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(example=json!({
    "title": "Test poll",
    "info": "This is a test poll",
    "ends": 1749382375.5,
    "images": [
        "ks5oa4p2y7cg7v3o3wg9kemw.png",
        "vxg491j2gjaf4k9nd0s89pv8.png",
        "g0s0x3f2iwtfa6cucahi1m9.png"
    ],
    "allowed_votes": 2,
    "group": "de7g5femt7hkfvymtowh0mkl"
}))]
pub struct AddPoll {
    pub title: String,
    pub info: String,
    /// timestamp in seconds (Unix time)
    pub ends: f64,
    pub images: HashSet<String>,
    pub allowed_votes: u32,
    pub group: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct PaginatedPoll {
    pub id: String,
    pub title: String,
    /// timestamp in seconds (Unix time)
    pub ends: f64,
    pub votes: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(example=json!({
    "polls": [
        {
            "id": "zfjox8wod9",
            "ends": 1749382375.5,
            "title": "This is a test poll",
            "votes": 0,
        },
    ],
    "page": 0,
    "page_count": 4,
}))]
pub struct FetchPolls {
    pub polls: Vec<PaginatedPoll>,
    pub page: u64,
    pub page_count: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(example=json!({
    "id": "zfjox8wod9",
    "title": "Test poll",
    "info": "This is a test poll",
    "ends": 1749382375.5,
    "allowed_votes": 2,
    "votes": 0,
    "images": [
        "ks5oa4p2y7cg7v3o3wg9kemw.png",
        "vxg491j2gjaf4k9nd0s89pv8.png",
        "g0s0x3f2iwtfa6cucahi1m9.png"
    ],
    "aspect_ratios": {
        "ks5oa4p2y7cg7v3o3wg9kemw.png": "16/9",
        "vxg491j2gjaf4k9nd0s89pv8.png": "1/1",
        "g0s0x3f2iwtfa6cucahi1m9.png": "16/9",
    },
    "group": "de7g5femt7hkfvymtowh0mkl",
    "updated_at": 1749382390.1,
}))]
pub struct FetchPoll {
    pub id: String,
    pub title: String,
    pub info: String,
    /// timestamp in seconds (Unix time)
    pub ends: f64,
    pub allowed_votes: u32,
    pub votes: u64,
    pub images: HashSet<String>,
    pub aspect_ratios: HashMap<String, String>,
    pub group: Option<String>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(example=json!({
    "title": "Renamed test poll",
    "allowed_votes": 1,
    "add_images": [
        "wqb9jl8tpg2xb9mgjtj10szw.png",
    ],
    "remove_images": [
        "ks5oa4p2y7cg7v3o3wg9kemw.png",
    ],
    "updated_at": 1749382391.1,
}))]
pub struct EditPoll {
    pub title: Option<String>,
    pub info: Option<String>,
    /// timestamp in seconds (Unix time)
    pub ends: Option<f64>,
    pub allowed_votes: Option<u32>,
    pub add_images: Option<HashSet<String>>,
    pub remove_images: Option<HashSet<String>>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(example=json!({
    "id": "zfjox8wod9",
    "ended": true,
    "public": false,
    "votes": {
        "vxg491j2gjaf4k9nd0s89pv8.png": 4,
        "g0s0x3f2iwtfa6cucahi1m9.png": 3,
        "wqb9jl8tpg2xb9mgjtj10szw.png": 1,
    },
    "updated_at": 1749382391.1,
}))]
pub struct FetchResults {
    pub id: String,
    pub ended: bool,
    pub public: bool,
    pub votes: HashMap<String, u64>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct PublishResults {
    pub published: bool,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct UpdatedPoll {
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct AddGroup {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(example=json!({
    "id": "k1220tpx7eyxlw4jrybe046y",
    "name": "test-group",
    "owner": "bqf7a2d9gbgud9a0jgfgt1ie",
    "members": [
        {"id" : "bqf7a2d9gbgud9a0jgfgt1ie"},
    ],
    "updated_at": 1749382410.283617,
}))]
pub struct FetchGroup {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub members: Vec<Member>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(example=json!({
    "name": "renamed-test-group",
    "owner": "w6m2ex14r2w261l499is87po",
    "updated_at": 1749382410.283617,
}))]
pub struct EditGroup {
    pub name: Option<String>,
    pub owner: Option<String>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct Member {
    pub id: String,
    // TODO name??
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(example=json!({
    "id": "zfjox8wod9",
    "title": "Renamed test poll",
    "info": "This is a test poll",
    "ends": 1749382375.5,
    "allowed_votes": 2,
    "images": [
        "wqb9jl8tpg2xb9mgjtj10szw.png",
        "vxg491j2gjaf4k9nd0s89pv8.png",
        "g0s0x3f2iwtfa6cucahi1m9.png"
    ],
    "aspect_ratios": {
        "wqb9jl8tpg2xb9mgjtj10szw.png": "16/9",
        "vxg491j2gjaf4k9nd0s89pv8.png": "1/1",
        "g0s0x3f2iwtfa6cucahi1m9.png": "16/9",
    },
}))]
pub struct FetchVotingPoll {
    pub id: String,
    pub title: String,
    pub info: String,
    /// timestamp in seconds (Unix time)
    pub ends: f64,
    pub allowed_votes: u32,
    pub images: HashSet<String>,
    pub aspect_ratios: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct FetchVote {
    /// timestamp in seconds (Unix time)
    pub created: f64,
    pub votes: HashSet<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(example=json!({
    "id": "zfjox8wod9",
    "first": "vxg491j2gjaf4k9nd0s89pv8.png",
    "second": "g0s0x3f2iwtfa6cucahi1m9.png",
    "third": "wqb9jl8tpg2xb9mgjtj10szw.png",
    "remaining": [],
}))]
pub struct FetchVoteResults {
    pub id: String,
    pub first: String,
    pub second: String,
    pub third: Option<String>,
    /// Remaining entries, in random order
    pub remaining: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(example=json!({
    "votes": [
        "vxg491j2gjaf4k9nd0s89pv8.png",
        "g0s0x3f2iwtfa6cucahi1m9.png",
    ],
}))]
pub struct Vote {
    pub votes: HashSet<String>,
}

#[derive(Serialize, PartialEq, Eq, Clone, Debug, utoipa::ToSchema)]
pub struct IdString(pub String);

impl IdString {
    pub fn new<S>(string: S) -> Result<Self, RestError>
    where
        S: Into<String>,
    {
        let s = string.into();

        // todo technically cuid2 allows only lowercase letters - so we could be even more restrictive here

        if s.chars().any(|c| !c.is_ascii_alphanumeric()) {
            return Err(RestError::bad_req("Invalid id"));
        }

        Ok(Self(s))
    }
}

impl Display for IdString {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for IdString {
    type Err = RestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IdString::new(s)
    }
}

impl<'de> Deserialize<'de> for IdString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        s.parse()
            .map_err(|_| de::Error::invalid_value(Unexpected::Str(&s), &"valid id"))
    }
}

#[derive(Serialize, PartialEq, Eq, Clone, Debug, utoipa::ToSchema)]
pub struct FileName(pub String);

impl FileName {
    pub fn new<P>(filename: P) -> Result<Self, RestError>
    where
        P: AsRef<Path>,
    {
        let err = Err(RestError::bad_req("Invalid filename".to_string()));

        let components = filename.as_ref().components().collect::<Vec<Component>>();

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

    use super::{FileName, IdString};

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

    #[test]
    fn test_id_string() {
        assert!(IdString::new("test").is_ok());
        assert!(IdString::new("test.txt").is_err());
        assert!("abcdefghijklmnop0123456789".parse::<IdString>().is_ok());
        assert!(".".parse::<IdString>().is_err());
        assert!("-".parse::<IdString>().is_err());
    }
}
