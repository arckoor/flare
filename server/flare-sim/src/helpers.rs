use std::{net::IpAddr, sync::Arc};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::{Method, Response};
use sea_entity::sea_orm_active_enums::Permissions;
use serde::Deserialize;
use tracing::info;

use crate::sim::{FLARE_PORT, FLARE_SERVER};
use flare::{
    api::api_params::{
        AddGroup, AddPoll, EditGroup, EditPoll, FetchGroup, FetchPoll, FetchPollSort, FetchPolls,
        FetchResults, FetchVote, FetchVoteResults, FetchVotingPoll, LoginInfo, Paginator,
        PublishResults, TokenResponse, UpdatedPoll, UploadedImage, UserInfo, Vote,
    },
    auth::jwt::AccessClaims,
};

pub struct Http {
    pub client: reqwest::Client,
    pub cookie_store: Arc<reqwest_cookie_store::CookieStoreMutex>,
    pub capture_bearer: bool,
    pub bearer: Option<String>,
    pub ip: String,
}

impl Http {
    pub fn new_with_cookies(capture_bearer: bool, ip: String) -> Self {
        let cookie_store = {
            let c = reqwest_cookie_store::CookieStore::default();
            let c = reqwest_cookie_store::CookieStoreMutex::new(c);
            Arc::new(c)
        };

        Self {
            client: reqwest::Client::builder()
                .cookie_provider(cookie_store.clone())
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            cookie_store,
            capture_bearer,
            bearer: None,
            ip,
        }
    }

    pub fn capture_bearer(&mut self, res: &Result<TokenResponse, reqwest::Error>) {
        if self.capture_bearer {
            if let Ok(token) = res {
                self.bearer = Some(token.access.unsecure().to_string());
            }
        }
    }

    pub fn clear_bearer(&mut self, res: &Result<Response, reqwest::Error>) {
        if let Ok(res) = res {
            if res.status().is_success() {
                self.bearer = None;
            }
        }
    }

    pub fn get_permissions(&self) -> Vec<Permissions> {
        self.bearer
            .as_ref()
            .map_or_else(Vec::new, |bearer| self.decode_claims(bearer).permissions)
    }

    pub fn get_groups(&self) -> Vec<String> {
        self.bearer
            .as_ref()
            .map_or_else(Vec::new, |bearer| self.decode_claims(bearer).groups)
    }

    fn decode_claims(&self, bearer: &str) -> AccessClaims {
        let key = DecodingKey::from_secret(&[]);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation();

        jsonwebtoken::decode::<AccessClaims>(&bearer, &key, &validation)
            .unwrap()
            .claims
    }

    #[must_use]
    pub fn request<S>(&self, host: IpAddr, port: u16, method: Method, path: S) -> RequestBuilder
    where
        S: Into<String>,
    {
        let url = format!("http://[{}]:{}{}", host, port, path.into());
        let builder = self.client.request(method, &url);
        let mut builder = RequestBuilder::new(builder).header("X-Forwarded-For", &self.ip);
        if let Some(bearer) = &self.bearer {
            builder = builder.bearer_auth(bearer.clone());
        }
        builder
    }

    #[must_use]
    pub fn get<S>(&self, host: IpAddr, port: u16, path: S) -> RequestBuilder
    where
        S: Into<String>,
    {
        self.request(host, port, Method::GET, path)
    }

    #[must_use]
    pub fn post<S>(&self, host: IpAddr, port: u16, path: S) -> RequestBuilder
    where
        S: Into<String>,
    {
        self.request(host, port, Method::POST, path)
    }

    #[must_use]
    pub fn put<S>(&self, host: IpAddr, port: u16, path: S) -> RequestBuilder
    where
        S: Into<String>,
    {
        self.request(host, port, Method::PUT, path)
    }

    #[must_use]
    pub fn patch<S>(&self, host: IpAddr, port: u16, path: S) -> RequestBuilder
    where
        S: Into<String>,
    {
        self.request(host, port, Method::PATCH, path)
    }

    #[must_use]
    pub fn delete<S>(&self, host: IpAddr, port: u16, path: S) -> RequestBuilder
    where
        S: Into<String>,
    {
        self.request(host, port, Method::DELETE, path)
    }
}

#[must_use]
pub fn get(client: &Http, url: &str) -> RequestBuilder {
    client.get(FLARE_SERVER, FLARE_PORT, url)
}

#[must_use]
pub fn post(client: &Http, url: &str) -> RequestBuilder {
    client.post(FLARE_SERVER, FLARE_PORT, url)
}

#[must_use]
pub fn put(client: &Http, url: &str) -> RequestBuilder {
    client.put(FLARE_SERVER, FLARE_PORT, url)
}

#[must_use]
pub fn patch(client: &Http, url: &str) -> RequestBuilder {
    client.patch(FLARE_SERVER, FLARE_PORT, url)
}

#[must_use]
pub fn delete(client: &Http, url: &str) -> RequestBuilder {
    client.delete(FLARE_SERVER, FLARE_PORT, url)
}

pub async fn req<R>(client: &Http, url: &str) -> Result<R, reqwest::Error>
where
    for<'de> R: Deserialize<'de>,
{
    get(client, url).send().await?.json::<R>().await
}

pub struct RequestBuilder {
    builder: reqwest::RequestBuilder,
}

impl RequestBuilder {
    fn new(builder: reqwest::RequestBuilder) -> Self {
        Self { builder }
    }

    pub fn bearer_auth(self, token: String) -> Self {
        Self {
            builder: self.builder.bearer_auth(token),
        }
    }

    pub fn json(self, body: &impl serde::Serialize) -> Self {
        Self {
            builder: self.builder.json(body),
        }
    }

    pub fn multipart(self, form: reqwest::multipart::Form) -> Self {
        Self {
            builder: self.builder.multipart(form),
        }
    }

    pub fn query(self, query: &impl serde::Serialize) -> Self {
        Self {
            builder: self.builder.query(query),
        }
    }

    pub fn header(self, key: &str, value: &str) -> Self {
        Self {
            builder: self.builder.header(key, value),
        }
    }

    pub async fn send(self) -> Result<Response, reqwest::Error> {
        self.builder.send().await?.error_for_status()
    }
}

pub fn logins() -> [LoginInfo; 5] {
    [
        LoginInfo {
            id: "admin".to_string(),
        },
        LoginInfo {
            id: "foo".to_string(),
        },
        LoginInfo {
            id: "bar".to_string(),
        },
        LoginInfo {
            id: "baz".to_string(),
        },
        LoginInfo {
            id: "tester".to_string(),
        },
    ]
}

pub fn png_images() -> [&'static [u8]; 10] {
    [
        include_bytes!("../../flare-test/images/0.png"),
        include_bytes!("../../flare-test/images/1.png"),
        include_bytes!("../../flare-test/images/2.png"),
        include_bytes!("../../flare-test/images/3.png"),
        include_bytes!("../../flare-test/images/4.png"),
        include_bytes!("../../flare-test/images/5.png"),
        include_bytes!("../../flare-test/images/6.png"),
        include_bytes!("../../flare-test/images/7.png"),
        include_bytes!("../../flare-test/images/8.png"),
        include_bytes!("../../flare-test/images/9.png"),
    ]
}

pub fn jpg_images() -> [&'static [u8]; 4] {
    [
        include_bytes!("../../flare-test/images/10.jpg"),
        include_bytes!("../../flare-test/images/11.jpg"),
        include_bytes!("../../flare-test/images/12.jpg"),
        include_bytes!("../../flare-test/images/13.jpg"),
    ]
}

pub async fn get_client(user: usize) -> (Http, String) {
    let login_info = &logins()[user];

    let mut client = Http::new_with_cookies(true, login_info.id.clone());

    login(&mut client, &login_info).await.unwrap();
    (client, login_info.id.clone())
}

pub async fn wait_for_api(client: &Http) {
    let mut i = 0;
    loop {
        let res = get(client, "/api/ping").send().await;
        if let Ok(res) = &res {
            if res.status().is_success() {
                break;
            }
        }
        i += 1;
        if i > 400 {
            tracing::error!("API did not respond: {:?}", res);
            panic!("API did not start");
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    info!("API is up after {} checks", i);
}

pub async fn upload_all_pngs(client: &Http) -> Vec<String> {
    upload_many_images(
        &client,
        &png_images()[..]
            .into_iter()
            .map(|i| (*i, "image/png"))
            .collect::<Vec<_>>(),
    )
    .await
}

pub async fn upload_many_pngs(client: &Http, start: usize, stop: usize) -> Vec<String> {
    upload_many_images(
        &client,
        &png_images()[start..stop]
            .into_iter()
            .map(|i| (*i, "image/png"))
            .collect::<Vec<_>>(),
    )
    .await
}

pub async fn upload_many_images(client: &Http, images: &[(&[u8], &str)]) -> Vec<String> {
    let mut imgs = Vec::new();
    for (image, mime) in images {
        let uploaded = add_image(&client, image, mime).await.unwrap();
        imgs.push(uploaded.name.clone());
    }
    imgs
}

pub async fn auth_ping(client: &Http) -> Result<(), reqwest::Error> {
    let _ = get(client, "/api/auth-ping").send().await?;
    Ok(())
}

pub async fn login(
    client: &mut Http,
    login_info: &LoginInfo,
) -> Result<TokenResponse, reqwest::Error> {
    let res = post(client, "/api/login")
        .json(login_info)
        .send()
        .await?
        .json::<TokenResponse>()
        .await;
    client.capture_bearer(&res);
    res
}

pub async fn refresh(client: &mut Http) -> Result<TokenResponse, reqwest::Error> {
    let res = post(client, "/api/refresh")
        .send()
        .await?
        .json::<TokenResponse>()
        .await;
    client.capture_bearer(&res);
    res
}

pub async fn user_info(client: &Http) -> Result<UserInfo, reqwest::Error> {
    get(client, "/api/user")
        .send()
        .await?
        .json::<UserInfo>()
        .await
}

pub async fn logout(client: &mut Http) -> Result<(), reqwest::Error> {
    let res = post(client, "/api/logout").send().await;
    client.clear_bearer(&res);
    res?;
    Ok(())
}

pub async fn remove_user(client: &Http) -> Result<(), reqwest::Error> {
    delete(client, "/api/user").send().await?;
    Ok(())
}

pub async fn fetch_image(client: &Http, name: &str) -> Result<Vec<u8>, reqwest::Error> {
    get(client, &format!("/api/image/{}", name))
        .send()
        .await?
        .bytes()
        .await
        .map(|b| b.to_vec())
}

pub async fn add_image(
    client: &Http,
    image: &[u8],
    mime: &str,
) -> Result<UploadedImage, reqwest::Error> {
    let part = reqwest::multipart::Part::bytes(image.to_vec())
        .file_name("image.png")
        .mime_str(mime)
        .unwrap();

    let form = reqwest::multipart::Form::new().part("image", part);

    post(&client, "/api/image")
        .multipart(form)
        .send()
        .await?
        .json::<UploadedImage>()
        .await
}

pub async fn remove_image(client: &Http, name: &str) -> Result<(), reqwest::Error> {
    delete(client, &format!("/api/image/{name}")).send().await?;
    Ok(())
}

pub async fn fetch_poll(client: &Http, poll_id: &str) -> Result<FetchPoll, reqwest::Error> {
    req(client, &format!("/api/poll/{poll_id}")).await
}

pub async fn fetch_polls(
    client: &Http,
    paginator: Option<Paginator<FetchPollSort>>,
) -> Result<FetchPolls, reqwest::Error> {
    let mut res = get(client, "/api/polls");
    if let Some(paginator) = paginator {
        res = res.query(&paginator);
    }
    res.send().await?.json::<FetchPolls>().await
}

pub async fn add_poll(client: &Http, add_poll: AddPoll) -> Result<FetchPoll, reqwest::Error> {
    post(client, "/api/poll")
        .json(&add_poll)
        .send()
        .await?
        .json::<FetchPoll>()
        .await
}

pub async fn edit_poll(
    client: &Http,
    poll_id: &str,
    edit_poll: EditPoll,
) -> Result<FetchPoll, reqwest::Error> {
    patch(client, &format!("/api/poll/{poll_id}"))
        .json(&edit_poll)
        .send()
        .await?
        .json::<FetchPoll>()
        .await
}

pub async fn remove_poll(client: &Http, poll_id: &str) -> Result<(), reqwest::Error> {
    delete(client, &format!("/api/poll/{poll_id}"))
        .send()
        .await?;

    Ok(())
}

pub async fn add_poll_to_group(
    client: &Http,
    poll_id: &str,
    group_id: &str,
    updated_poll: UpdatedPoll,
) -> Result<UpdatedPoll, reqwest::Error> {
    patch(client, &format!("/api/poll/{poll_id}/{group_id}"))
        .json(&updated_poll)
        .send()
        .await?
        .json::<UpdatedPoll>()
        .await
}

pub async fn fetch_results(client: &Http, poll_id: &str) -> Result<FetchResults, reqwest::Error> {
    req(client, &format!("/api/poll/{}/results", poll_id)).await
}

pub async fn publish_results(
    client: &Http,
    poll_id: &str,
    publish_results: PublishResults,
) -> Result<UpdatedPoll, reqwest::Error> {
    post(client, &format!("/api/poll/{poll_id}/results"))
        .json(&publish_results)
        .send()
        .await?
        .json::<UpdatedPoll>()
        .await
}

pub async fn join_group(client: &Http, group_id: &str) -> Result<(), reqwest::Error> {
    post(client, &format!("/api/group/{group_id}"))
        .send()
        .await?;

    Ok(())
}

pub async fn leave_group(client: &Http, group_id: &str) -> Result<(), reqwest::Error> {
    delete(client, &format!("/api/group/{group_id}"))
        .send()
        .await?;

    Ok(())
}

pub async fn add_group(client: &Http, add_group: AddGroup) -> Result<FetchGroup, reqwest::Error> {
    post(client, "/api/groups")
        .json(&add_group)
        .send()
        .await?
        .json::<FetchGroup>()
        .await
}

pub async fn fetch_group(client: &Http, group_id: &str) -> Result<FetchGroup, reqwest::Error> {
    req(client, &format!("/api/groups/{group_id}")).await
}

pub async fn edit_group(
    client: &Http,
    group_id: &str,
    edit_group: EditGroup,
) -> Result<(), reqwest::Error> {
    patch(client, &format!("/api/groups/{group_id}"))
        .json(&edit_group)
        .send()
        .await?;

    Ok(())
}

pub async fn remove_group(client: &Http, group_id: &str) -> Result<(), reqwest::Error> {
    delete(client, &format!("/api/groups/{group_id}"))
        .send()
        .await?;

    Ok(())
}

pub async fn add_group_user(
    client: &Http,
    group_id: &str,
    user_id: &str,
) -> Result<(), reqwest::Error> {
    post(client, &format!("/api/groups/{group_id}/{user_id}"))
        .send()
        .await?;

    Ok(())
}

pub async fn remove_group_user(
    client: &Http,
    group_id: &str,
    user_id: &str,
) -> Result<(), reqwest::Error> {
    delete(client, &format!("/api/groups/{group_id}/{user_id}"))
        .send()
        .await?;

    Ok(())
}

pub async fn fetch_voting_image(client: &Http, image_id: &str) -> Result<Vec<u8>, reqwest::Error> {
    get(client, &format!("/api/v/image/{image_id}"))
        .send()
        .await?
        .bytes()
        .await
        .map(|b| b.to_vec())
}

pub async fn fetch_voting_poll(
    client: &Http,
    poll_id: &str,
) -> Result<FetchVotingPoll, reqwest::Error> {
    req(client, &format!("/api/v/poll/{poll_id}")).await
}

pub async fn fetch_vote(client: &Http, poll_id: &str) -> Result<FetchVote, reqwest::Error> {
    req(client, &format!("/api/v/poll/{poll_id}/vote")).await
}

pub async fn vote(client: &Http, poll_id: &str, vote: Vote) -> Result<(), reqwest::Error> {
    post(client, &format!("/api/v/poll/{poll_id}/vote"))
        .json(&vote)
        .send()
        .await?;

    Ok(())
}

pub async fn fetch_voting_results(
    client: &Http,
    poll_id: &str,
) -> Result<FetchVoteResults, reqwest::Error> {
    req(client, &format!("/api/v/poll/{poll_id}/results")).await
}
