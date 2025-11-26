use std::collections::HashMap;

use flare::api::api_params::{AddPoll, EditGroup, LoginInfo};
use flare_sim::{
    helpers::{
        Http, add_poll, auth_ping, delete, edit_group, fetch_group, fetch_poll, fetch_voting_image,
        fetch_voting_poll, get, get_client, login, refresh, remove_group, remove_user,
        upload_all_pngs, user_info,
    },
    sim::setup_db,
    test_builder::flare_test,
    turmoil,
};
use reqwest::StatusCode;
use sea_entity::sea_orm_active_enums::OauthProvider;
use sea_orm::entity::prelude::*;

#[test]
fn test_oauth() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            // this doesn't really test oauth at all, but it's the best we can do
            let client = get_client(0).await.0;

            for provider in vec!["discord", "github"] {
                assert_eq!(
                    get(&client, &format!("/api/oauth/{provider}/login"))
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    StatusCode::FOUND
                );

                assert_eq!(
                    get(&client, &format!("/api/oauth/{provider}/callback"))
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    StatusCode::FOUND
                );

                let query = [("code", "test_code"), ("state", "test_state")]
                    .into_iter()
                    .collect::<HashMap<_, _>>();

                assert_eq!(
                    get(&client, &format!("/api/oauth/{provider}/callback"))
                        .query(&query)
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    StatusCode::FOUND
                );
            }

            assert!(
                get(&client, "/api/oauth/made-up-provider/login")
                    .send()
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_account_linking() -> turmoil::Result {
    flare_test(|sim| {
        sim.client("client", async move {
            let db = setup_db().await;

            let user_oauth_id = "oauth-1234".to_string();
            let github_provider = OauthProvider::Github;
            let discord_provider = OauthProvider::Discord;

            let user = db
                .get_or_create_or_link_oauth_user(user_oauth_id.clone(), github_provider, None)
                .await
                .unwrap();

            assert!(
                sea_entity::o_auth_user::Entity::find_by_id((user.id.clone(), github_provider))
                    .one(&db.sea)
                    .await
                    .unwrap()
                    .is_some()
            );

            // our user + admin
            assert_eq!(
                sea_entity::user::Entity::find()
                    .all(&db.sea)
                    .await
                    .unwrap()
                    .len(),
                2
            );

            let same_user = db
                .get_or_create_or_link_oauth_user(user_oauth_id.clone(), github_provider, None)
                .await
                .unwrap();

            // can't link to user that doesn't exist
            assert!(
                db.get_or_create_or_link_oauth_user(
                    user_oauth_id.clone(),
                    discord_provider,
                    Some("non-existant-user".to_string()),
                )
                .await
                .is_err()
            );

            // we link another provider to the user
            let linked_user = db
                .get_or_create_or_link_oauth_user(
                    user_oauth_id.clone(),
                    discord_provider,
                    Some(user.id.clone()),
                )
                .await
                .unwrap();

            // should be the same one
            assert_eq!(user, same_user);
            assert_eq!(user, linked_user);

            // can't link two of the same provider
            assert!(
                db.get_or_create_or_link_oauth_user(
                    "some-github-id".to_string(),
                    github_provider,
                    Some(user.id.clone())
                )
                .await
                .is_err()
            );

            let other_oauth_user_id = "4567-oauth".to_string();

            let other_user = db
                .get_or_create_or_link_oauth_user(
                    other_oauth_user_id.clone(),
                    github_provider,
                    None,
                )
                .await
                .unwrap();

            assert_ne!(user, other_user);

            // trying to link an already linked account
            assert!(
                db.get_or_create_or_link_oauth_user(
                    user_oauth_id.clone(),
                    discord_provider,
                    Some(other_user.id.clone())
                )
                .await
                .is_err()
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_account_unlinking() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            // we run the migrations twice here, which also gets rid of all the stuff the setup does, but oh well
            let db = setup_db().await;

            let github_oauth_id = "discord-a".to_string();
            let discord_oauth_id = "github-a".to_string();
            let github_provider = OauthProvider::Github;
            let discord_provider = OauthProvider::Discord;

            let user = db
                .get_or_create_or_link_oauth_user(github_oauth_id.clone(), github_provider, None)
                .await
                .unwrap();

            db.get_or_create_or_link_oauth_user(
                discord_oauth_id.clone(),
                discord_provider,
                Some(user.id.clone()),
            )
            .await
            .unwrap();

            let mut client = Http::new_with_cookies(true, "client".to_string());
            login(
                &mut client,
                &LoginInfo {
                    id: user.id.clone(),
                },
            )
            .await
            .unwrap();

            let info = user_info(&client).await.unwrap();
            assert_eq!(*info.logins.get(&github_provider).unwrap(), github_oauth_id);
            assert_eq!(
                *info.logins.get(&discord_provider).unwrap(),
                discord_oauth_id
            );

            // unlink github
            assert!(
                delete(&client, "/api/oauth/github/unlink")
                    .send()
                    .await
                    .is_ok()
            );

            assert!(
                auth_ping(&client)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );

            refresh(&mut client).await.unwrap();

            // already unlinked, doesn't exist anymore
            assert!(
                delete(&client, "/api/oauth/github/unlink")
                    .send()
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            let info = user_info(&client).await.unwrap();
            assert_eq!(
                *info.logins.get(&discord_provider).unwrap(),
                discord_oauth_id
            );
            assert!(!info.logins.contains_key(&github_provider));

            // relink github
            db.get_or_create_or_link_oauth_user(
                github_oauth_id.clone(),
                github_provider,
                Some(user.id.clone()),
            )
            .await
            .unwrap();

            // unlink discord
            assert!(
                delete(&client, "/api/oauth/discord/unlink")
                    .send()
                    .await
                    .is_ok()
            );

            refresh(&mut client).await.unwrap();

            let info = user_info(&client).await.unwrap();
            assert_eq!(*info.logins.get(&github_provider).unwrap(), github_oauth_id);
            assert!(!info.logins.contains_key(&discord_provider));

            // try to unlink github too, but last account left so it should fail
            assert!(
                delete(&client, "/api/oauth/github/unlink")
                    .send()
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );

            // we can use the unlinked discord account to make a new account
            let new_user = db
                .get_or_create_or_link_oauth_user(discord_oauth_id.clone(), discord_provider, None)
                .await
                .unwrap();

            assert_ne!(user.id, new_user.id);

            // link a completely new discord account
            db.get_or_create_or_link_oauth_user(
                "12345-discord".to_string(),
                discord_provider,
                Some(user.id.clone()),
            )
            .await
            .unwrap();

            refresh(&mut client).await.unwrap();

            // can't link a second account of the same provider
            assert!(
                db.get_or_create_or_link_oauth_user(
                    "67890-discord".to_string(),
                    discord_provider,
                    Some(user.id.clone()),
                )
                .await
                .is_err()
            );

            assert!(
                delete(&client, "/api/oauth/discord/unlink")
                    .send()
                    .await
                    .is_ok()
            );

            refresh(&mut client).await.unwrap();

            // but after deleting the previous one, it works
            assert!(
                db.get_or_create_or_link_oauth_user(
                    "67890-discord".to_string(),
                    discord_provider,
                    Some(user.id.clone()),
                )
                .await
                .is_ok()
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_remove_user() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();
        sim.group_users("test-group", 1, vec![2, 3]);
        sim.group_users("other-group", 1, vec![2]);

        sim.client("client", async move {
            let (mut client, client_id) = get_client(1).await;
            let (mut user_3, user_2_id) = get_client(3).await;

            let images = upload_all_pngs(&client).await;

            let groups = client.get_groups();

            let (small_group, big_group, big_group_updated_at) = {
                let group_0 = fetch_group(&client, &groups[0]).await.unwrap();
                let group_1 = fetch_group(&client, &groups[1]).await.unwrap();
                if group_0.members.len() == 2 {
                    (group_0.id, group_1.id, group_1.updated_at)
                } else {
                    (group_1.id, group_0.id, group_0.updated_at)
                }
            };

            let client_poll = add_poll(
                &client,
                AddPoll {
                    title: "test-poll".to_string(),
                    info: "test".to_string(),
                    ends: f64::MAX,
                    images: [images[0].clone(), images[1].clone(), images[2].clone()].into(),
                    voting_limit: 2,
                    group: None,
                },
            )
            .await
            .unwrap();

            let group_poll = add_poll(
                &client,
                AddPoll {
                    title: "other-poll".to_string(),
                    info: "test".to_string(),
                    ends: f64::MAX,
                    images: [images[4].clone(), images[5].clone(), images[6].clone()].into(),
                    voting_limit: 2,
                    group: Some(big_group.parse().unwrap()),
                },
            )
            .await
            .unwrap();

            // we have many two groups
            assert!(
                remove_user(&client)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );

            remove_group(&client, &small_group).await.unwrap();
            refresh(&mut client).await.unwrap();

            // just the group with the poll remains
            assert!(
                remove_user(&client)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );

            edit_group(
                &client,
                &big_group,
                EditGroup {
                    name: None,
                    owner: Some(user_2_id.parse().unwrap()),
                    updated_at: big_group_updated_at,
                },
            )
            .await
            .unwrap();

            refresh(&mut client).await.unwrap();
            refresh(&mut user_3).await.unwrap();

            assert!(remove_user(&client).await.is_ok());

            assert!(
                auth_ping(&client)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );
            // our refresh cookie is gone
            assert!(
                refresh(&mut client)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED))
            );

            assert!(
                fetch_voting_poll(&user_3, &client_poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            let group_poll = fetch_poll(&user_3, &group_poll.id).await.unwrap();
            assert_eq!(group_poll.images.len(), 3);
            for image in group_poll.images {
                assert!(fetch_voting_image(&user_3, &image).await.is_ok());
            }

            let group = fetch_group(&user_3, &big_group).await.unwrap();
            assert!(
                !group
                    .members
                    .into_iter()
                    .map(|m| m.id)
                    .collect::<Vec<_>>()
                    .contains(&client_id)
            );

            assert_eq!(group.owner, user_2_id);

            let admin = get_client(0).await.0;

            // admin can't delete themselves
            assert!(
                remove_user(&admin)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );

            Ok(())
        });

        sim.run()
    })
}
