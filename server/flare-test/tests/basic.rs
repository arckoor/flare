use reqwest::StatusCode;
use sea_entity::sea_orm_active_enums::Permissions;
use tokio::time::sleep;

use flare_sim::helpers::{Http, auth_ping, get, get_client, login, logins, logout, post, refresh};
use flare_sim::sim::DELAY;
use flare_sim::test_builder::flare_test;
use flare_sim::turmoil;

#[test]
fn test_tokens() -> turmoil::Result {
    flare_test(|sim| {
        sim.start_api();

        sim.client("client", async move {
            let mut client = Http::new_with_cookies(false, "client".to_string());

            let token = login(&mut client, &logins()[0]).await.unwrap();
            let access_token = token.access.unsecure().to_string();

            assert!(
                get(&client, "/api/auth-ping")
                    .bearer_auth(access_token.clone())
                    .send()
                    .await
                    .is_ok()
            );

            let new_access_token = loop {
                sleep(DELAY).await;
                let new_token = refresh(&mut client).await.unwrap();
                let new_access_token = new_token.access.unsecure().to_string();
                if new_access_token != access_token {
                    break new_access_token;
                }
            };
            // useless assert, but it makes it clear what we want to happen
            assert_ne!(access_token, new_access_token);

            assert!(
                get(&client, "/api/auth-ping")
                    .bearer_auth(access_token.clone())
                    .send()
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );

            assert!(
                get(&client, "/api/auth-ping")
                    .bearer_auth(new_access_token.clone())
                    .send()
                    .await
                    .is_ok()
            );

            assert_eq!(
                client.cookie_store.lock().unwrap().iter_unexpired().count(),
                2
            );

            post(&client, "/api/logout")
                .bearer_auth(new_access_token.clone())
                .send()
                .await
                .unwrap();

            assert_eq!(
                client.cookie_store.lock().unwrap().iter_unexpired().count(),
                0
            );

            assert!(
                get(&client, "/api/auth-ping")
                    .bearer_auth(new_access_token.clone())
                    .send()
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );

            assert!(
                refresh(&mut client)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED))
            );

            let mut client = get_client(0).await.0;
            assert!(auth_ping(&client).await.is_ok());

            let bearer = client.bearer.unwrap();
            let parts = bearer.split(".").collect::<Vec<&str>>();
            let header = parts[0];
            let claims = parts[1];

            client.bearer = Some("header.invalid.made-up-signature".to_string());
            assert!(
                auth_ping(&client)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED))
            );

            // properly formatted token
            client.bearer = Some(format!("{}.{}.bWFkZS11cC1zaWduYXR1cmU", header, claims));
            assert!(
                auth_ping(&client)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED))
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_basic_scenario() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let mut client = get_client(0).await.0;

            assert!(get(&client, "/api/auth-ping").send().await.is_ok());

            assert!(client.get_permissions().contains(&Permissions::Admin));

            assert!(get(&client, "/api/docs/openapi.json").send().await.is_ok());

            assert!(logout(&mut client).await.is_ok());

            Ok(())
        });

        sim.run()
    })
}
