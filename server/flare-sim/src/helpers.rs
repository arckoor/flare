use std::{net::IpAddr, sync::Arc};

use flare::api::api_params::{LoginInfo, TokenResponse};
use reqwest::{Method, RequestBuilder, Response};
use serde::Deserialize;

use crate::sim::{FLARE_PORT, FLARE_SERVER};

pub struct Http {
    pub client: reqwest::Client,
    pub cookie_store: Arc<reqwest_cookie_store::CookieStoreMutex>,
}

impl Http {
    pub fn new_with_cookies() -> Self {
        let cookie_store = reqwest_cookie_store::CookieStore::default();
        let cookie_store = reqwest_cookie_store::CookieStoreMutex::new(cookie_store);
        let cookie_store = std::sync::Arc::new(cookie_store);
        Self {
            client: reqwest::Client::builder()
                .cookie_provider(cookie_store.clone())
                .build()
                .unwrap(),
            cookie_store,
        }
    }

    #[must_use]
    pub fn request<S>(&self, host: IpAddr, port: u16, method: Method, path: S) -> RequestBuilder
    where
        S: Into<String>,
    {
        let url = format!("http://[{}]:{}{}", host, port, path.into());
        self.client.request(method, &url)
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

pub async fn signup(client: &Http, login_info: &LoginInfo) -> Result<(), reqwest::Error> {
    post(client, "/api/signup")
        .json(login_info)
        .send()
        .await
        .unwrap()
        .error_for_status()?;
    Ok(())
}

pub async fn login(client: &Http, login_info: &LoginInfo) -> Result<TokenResponse, reqwest::Error> {
    post(client, "/api/login")
        .json(login_info)
        .send()
        .await?
        .error_for_status()?
        .json::<TokenResponse>()
        .await
}

pub async fn refresh(client: &Http) -> Result<TokenResponse, reqwest::Error> {
    get(client, "/api/refresh")
        .send()
        .await?
        .error_for_status()?
        .json::<TokenResponse>()
        .await
}

pub async fn logout(client: &Http, token: String) -> Result<Response, reqwest::Error> {
    get(client, "/api/logout")
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .error_for_status()
}
