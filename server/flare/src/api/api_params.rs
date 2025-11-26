use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    os::unix::ffi::OsStrExt,
    path::{Component, Path},
    str::FromStr,
};

use sea_entity::{api_params::RecurrenceRule, sea_orm_active_enums::OauthProvider};
use secstr::SecUtf8;
use serde::{
    Deserialize, Serialize,
    de::{self, Unexpected},
};

use crate::{
    api::error::RestError,
    crypto::secstr::{deserialize_secutf8, serialize_secutf8},
};

const fn default_page_size() -> u64 {
    10
}

const fn default_page() -> u64 {
    0
}

pub trait PaginatedSort: utoipa::ToSchema {}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FetchPollSort {
    /// default
    CreatedAt,
    Title,
    Ends,
}

impl PaginatedSort for FetchPollSort {}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FetchScheduledPollSort {
    /// default
    NextOccurrence,
    CreatedAt,
}

impl PaginatedSort for FetchScheduledPollSort {}

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
#[schema(examples(json!(UserInfo {
    logins: [
        (OauthProvider::Discord, "discord-user-id".to_string()),
        (OauthProvider::Github, "github-user-id".to_string())
    ].into(),
})))]
pub struct UserInfo {
    /// map from an oauth provider to the oauth id
    pub logins: HashMap<OauthProvider, String>,
}

#[derive(utoipa::ToSchema)]
pub struct AddImage {
    #[schema(format = Binary)]
    pub image: String,
}

#[derive(Serialize, Deserialize, Debug, utoipa::ToSchema)]
pub struct UploadedImage {
    /// The name assigned to the image
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(FetchPolls {
    polls: vec![PaginatedPoll {
        id: "zfjox8wod9".to_string(),
        ends: 1749382375.524451,
        title: "Test poll".to_string(),
        votes: 0,
    }],
    page: 0,
    page_count: 4
})))]
pub struct FetchPolls {
    pub polls: Vec<PaginatedPoll>,
    pub page: u64,
    pub page_count: u64,
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
#[schema(examples(json!(AddPoll {
    title: "Test poll".to_string(),
    info: "This is a test poll".to_string(),
    ends: 1749382375.524451,
    images: [
        "ks5oa4p2y7cg7v3o3wg9kemw.png".to_string(),
        "vxg491j2gjaf4k9nd0s89pv8.png".to_string(),
        "g0s0x3f2iwtfa6cucahi1m9.png".to_string(),
    ].into(),
    voting_limit: 2,
    group: Some("de7g5femt7hkfvymtowh0mkl".parse().unwrap()),
})))]
pub struct AddPoll {
    pub title: String,
    pub info: String,
    /// timestamp in seconds (Unix time)
    pub ends: f64,
    pub images: HashSet<String>,
    pub voting_limit: u32,
    pub group: Option<IdString>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(FetchPoll {
    id: "zfjox8wod9".to_string(),
    title: "Test poll".to_string(),
    info: "This is a test poll".to_string(),
    ends: 1749382375.524451,
    voting_limit: 2,
    votes: 2,
    images: [
        "ks5oa4p2y7cg7v3o3wg9kemw.png".to_string(),
        "vxg491j2gjaf4k9nd0s89pv8.png".to_string(),
        "g0s0x3f2iwtfa6cucahi1m9.png".to_string(),
    ].into(),
    aspect_ratios: [
        ("ks5oa4p2y7cg7v3o3wg9kemw.png".to_string(), "16/9".to_string()),
        ("vxg491j2gjaf4k9nd0s89pv8".to_string(), "1/1".to_string()),
        ("g0s0x3f2iwtfa6cucahi1m9".to_string(), "16/9".to_string()),
    ].into(),
    group: Some("de7g5femt7hkfvymtowh0mkl".to_string()),
    updated_at: 1749382390.16360,
})))]
pub struct FetchPoll {
    pub id: String,
    pub title: String,
    pub info: String,
    /// timestamp in seconds (Unix time)
    pub ends: f64,
    pub voting_limit: u32,
    pub votes: u64,
    pub images: HashSet<String>,
    pub aspect_ratios: HashMap<String, String>,
    pub group: Option<String>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(EditPoll {
    title: Some("Renamed test poll".to_string()),
    info: None,
    ends: None,
    voting_limit: Some(1),
    add_images: Some(["wqb9jl8tpg2xb9mgjtj10szw.png".to_string()].into()),
    remove_images: Some(["ks5oa4p2y7cg7v3o3wg9kemw.png".to_string()].into()),
    updated_at: 1749382390.16360,
})))]
pub struct EditPoll {
    pub title: Option<String>,
    pub info: Option<String>,
    /// timestamp in seconds (Unix time)
    pub ends: Option<f64>,
    pub voting_limit: Option<u32>,
    pub add_images: Option<HashSet<String>>,
    pub remove_images: Option<HashSet<String>>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(FetchResults {
    id: "zfjox8wod9".to_string(),
    ended: true,
    public: false,
    votes: [
        ("vxg491j2gjaf4k9nd0s89pv8.png".to_string(), 4),
        ("g0s0x3f2iwtfa6cucahi1m9.png".to_string(), 3),
        ("wqb9jl8tpg2xb9mgjtj10szw.png".to_string(), 1),
    ].into(),
    updated_at: 1749382391.83425
})))]
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
pub struct FetchScheduledPolls {
    pub polls: Vec<FetchScheduledPoll>,
    pub page: u64,
    pub page_count: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(AddScheduledPoll {
    id: Some("my-custom-id".parse().unwrap()),
    name: "My scheduled poll".to_string(),
    first_occurrence: 1750089600.0,
    cutoff: 86400.0,
    recurrence_rule: Some(RecurrenceRule::DaysBeforeEndOfMonth { days: 4 }),
    submission_limit: Some(3),
    needs_approval: false,
    reject_duplicates: true,
    title_template: "Scheduled poll".to_string(),
    info: "You're allowed to submit cute cat pictures.".to_string(),
    voting_limit: 3,
    voting_duration: 604800.0,
    group: None,
})))]
pub struct AddScheduledPoll {
    pub id: Option<IdString>,
    pub name: String,
    pub first_occurrence: f64,
    pub cutoff: f64,
    pub recurrence_rule: Option<RecurrenceRule>,
    pub submission_limit: Option<u32>,
    pub needs_approval: bool,
    pub title_template: String,
    pub info: String,
    pub reject_duplicates: bool,
    pub voting_limit: u32,
    pub voting_duration: f64,
    pub group: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(EditScheduledPoll {
    name: None,
    next_occurrence: None,
    cutoff: None,
    recurrence_rule: Some(Some(RecurrenceRule::Weekly { interval_weeks: 1 })),
    submission_limit: Some(None),
    needs_approval: Some(true),
    reject_duplicates: None,
    title_template: None,
    info: None,
    voting_limit: None,
    voting_duration: None,
    updated_at: 1749382390.16360
})))]
pub struct EditScheduledPoll {
    pub name: Option<String>,
    pub next_occurrence: Option<f64>,
    pub cutoff: Option<f64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "::serde_with::rust::double_option"
    )]
    pub recurrence_rule: Option<Option<RecurrenceRule>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "::serde_with::rust::double_option"
    )]
    pub submission_limit: Option<Option<u32>>,
    pub needs_approval: Option<bool>,
    pub reject_duplicates: Option<bool>,
    pub title_template: Option<String>,
    pub info: Option<String>,
    pub voting_limit: Option<u32>,
    pub voting_duration: Option<f64>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(FetchScheduledPoll {
    id: "my-custom-id".to_string(),
    name: "My scheduled poll".to_string(),
    polls: vec![],
    updated_at: 1749382390.16360
})))]
pub struct FetchScheduledPoll {
    pub id: String,
    pub name: String,
    pub polls: Vec<String>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct FetchScheduledPollSubmissions {
    pub submissions: Vec<ScheduledPollSubmission>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct ScheduledPollSubmission {
    pub image_id: String,
    pub user_id: String,
    pub approved: bool,
    pub submitted_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct ApproveScheduledPollSubmission {
    pub image_id: String,
    pub approved: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct FetchScheduledPollSubmission {
    pub images: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct EditScheduledPollSubmission {
    pub add_images: Vec<String>,
    pub remove_images: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct AddGroup {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(FetchGroup {
    id: "k1220tpx7eyxlw4jrybe046y".to_string(),
    name: "test-group".to_string(),
    owner: "bqf7a2d9gbgud9a0jgfgt1ie".to_string(),
    members: vec![Member {
        id: "bqf7a2d9gbgud9a0jgfgt1ie".to_string()
    }],
    updated_at: 1749382410.283617
})))]
pub struct FetchGroup {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub members: Vec<Member>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(EditGroup {
    name: Some("renamed-test-group".to_string()),
    owner: Some("w6m2ex14r2w261l499is87po".parse().unwrap()),
    updated_at: 1749382410.283617,
})))]
pub struct EditGroup {
    pub name: Option<String>,
    pub owner: Option<IdString>,
    /// timestamp in seconds (Unix time)
    pub updated_at: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
pub struct Member {
    pub id: String,
    // TODO name??
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(FetchVotingPoll {
    id: "zfjox8wod9".to_string(),
    title: "Renamed test poll".to_string(),
    info: "This is a test poll".to_string(),
    ends: 1749382375.51251,
    voting_limit: 2,
    images: [
        "wqb9jl8tpg2xb9mgjtj10szw.png".to_string(),
        "vxg491j2gjaf4k9nd0s89pv8.png".to_string(),
        "g0s0x3f2iwtfa6cucahi1m9.png".to_string(),
    ].into(),
    aspect_ratios: [
        ("wqb9jl8tpg2xb9mgjtj10szw.png".to_string(), "16/9".to_string()),
        ("vxg491j2gjaf4k9nd0s89pv8".to_string(), "1/1".to_string()),
        ("g0s0x3f2iwtfa6cucahi1m9".to_string(), "16/9".to_string()),
    ].into()
})))]
pub struct FetchVotingPoll {
    pub id: String,
    pub title: String,
    pub info: String,
    /// timestamp in seconds (Unix time)
    pub ends: f64,
    pub voting_limit: u32,
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
#[schema(examples(json!(FetchVoteResults {
    id: "zfjox8wod9".to_string(),
    first: vec!["vxg491j2gjaf4k9nd0s89pv8.png".to_string()],
    second: vec!["g0s0x3f2iwtfa6cucahi1m9.png".to_string()],
    third: vec!["wqb9jl8tpg2xb9mgjtj10szw.png".to_string()],
    remaining: vec![],
})))]
pub struct FetchVoteResults {
    pub id: String,
    pub first: Vec<String>,
    pub second: Vec<String>,
    pub third: Vec<String>,
    /// Remaining entries, in random order
    pub remaining: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[schema(examples(json!(Vote {
    votes: [
    "vxg491j2gjaf4k9nd0s89pv8.png".to_string(),
    "g0s0x3f2iwtfa6cucahi1m9.png".to_string()
    ].into(),
})))]
pub struct Vote {
    pub votes: HashSet<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Task {
    CleanOldInvites,
    CleanOldImages,
    LockOldPolls,
    RunScheduledPoll(IdString),
}

#[derive(Serialize, PartialEq, Eq, Clone, Debug, utoipa::ToSchema)]
#[schema(pattern = r"^[a-zA-Z0-9\-]+$", examples(json!(IdString::new("bqf7a2d9gbgud9a0jgfgt1ie").unwrap())))]
pub struct IdString(pub String);

impl IdString {
    pub fn new<S>(string: S) -> Result<Self, RestError>
    where
        S: Into<String>,
    {
        let s = string.into();

        if s.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-') {
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
#[schema(pattern = r"^[a-zA-Z0-9\.]+$", examples(json!(FileName::new("vxg491j2gjaf4k9nd0s89pv8.png").unwrap())))]
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
        assert!("abcdefghijklmnop0123456789-".parse::<IdString>().is_ok());
        assert!("some-poll".parse::<IdString>().is_ok());
        assert!(".".parse::<IdString>().is_err());
    }
}
