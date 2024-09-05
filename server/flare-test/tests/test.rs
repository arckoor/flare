use flare::api::api_params::LoginInfo;
use flare_sim::helpers::{get, login, logout, refresh, signup, Http};
use flare_sim::sim::START_DELAY;
use flare_sim::test_builder::flare_test;
use flare_sim::turmoil;
use reqwest::StatusCode;
use secstr::SecStr;
use tokio::time::sleep;

#[test]
fn test_signup() -> turmoil::Result {
    flare_test(|sim| {
        sim.start_api();
        sim.client("client", async move {
            sleep(START_DELAY).await;

            let mut client = Http::new_with_cookies(false);

            let login_info = LoginInfo {
                username: "test".to_string(),
                password: SecStr::from("test"),
            };

            signup(&client, &login_info).await.unwrap();
            let token = login(&mut client, &login_info).await.unwrap();

            assert!(get(&client, "/api/test-protected-route")
                .bearer_auth(token.access.clone())
                .send()
                .await
                .is_ok());

            sleep(START_DELAY).await;
            let new_token = refresh(&mut client).await.unwrap();
            assert_ne!(token.access, new_token.access);

            assert!(get(&client, "/api/test-protected-route")
                .bearer_auth(token.access)
                .send()
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED)));

            assert!(get(&client, "/api/test-protected-route")
                .bearer_auth(new_token.access.clone())
                .send()
                .await
                .is_ok());

            logout(&mut client, new_token.access.clone()).await.unwrap();

            assert!(get(&client, "/api/test-protected-route")
                .bearer_auth(new_token.access)
                .send()
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED)));

            Ok(())
        });

        sim.run()
    })
}
