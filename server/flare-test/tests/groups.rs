use flare::api::api_params::{AddGroup, EditGroup};
use flare_sim::{
    helpers::{
        add_group, add_group_user, auth_ping, edit_group, fetch_group, get_client, join_group,
        leave_group, refresh, remove_group, remove_group_user,
    },
    test_builder::flare_test,
    turmoil,
};
use reqwest::StatusCode;

#[test]
fn test_groups() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let (mut client, client_id) = get_client(0, false).await.unwrap();
            let (mut user_a, user_a_id) = get_client(1, false).await.unwrap();
            let (mut user_b, user_b_id) = get_client(2, false).await.unwrap();

            let group = add_group(
                &client,
                AddGroup {
                    name: "test-group".to_string(),
                },
            )
            .await
            .unwrap();

            assert!(group.members.len() == 1);
            assert!(group.members[0].id == client_id);
            assert!(group.name == "test-group");

            assert!(
                auth_ping(&client)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED))
            );
            refresh(&mut client).await.unwrap();

            let fetched_group = fetch_group(&client, &group.id).await.unwrap();
            assert!(fetched_group.members.len() == 1);
            assert!(fetched_group.members[0].id == client_id);
            assert!(fetched_group.name == "test-group");

            assert!(
                fetch_group(&user_a, &group.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            add_group_user(&client, &group.id, &user_a_id)
                .await
                .unwrap();

            join_group(&user_a, &group.id).await.unwrap();

            assert!(
                auth_ping(&user_a)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED))
            );

            refresh(&mut user_a).await.unwrap();

            let fetched_group = fetch_group(&user_a, &group.id).await.unwrap();
            assert!(fetched_group.owner == client_id);
            assert!(fetched_group.members.len() == 2);
            assert!(fetched_group.members[0].id == client_id);
            assert!(fetched_group.members[1].id == user_a_id);
            assert!(fetched_group.name == "test-group");

            add_group_user(&client, &group.id, &user_b_id)
                .await
                .unwrap();
            join_group(&user_b, &group.id).await.unwrap();
            refresh(&mut user_b).await.unwrap();

            let fetched_group = fetch_group(&client, &group.id).await.unwrap();
            assert!(fetched_group.members.len() == 3);

            remove_group_user(&client, &group.id, &user_b_id)
                .await
                .unwrap();

            assert!(
                auth_ping(&user_b)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED))
            );
            refresh(&mut user_b).await.unwrap();

            let fetched_group = fetch_group(&client, &group.id).await.unwrap();
            assert!(fetched_group.members.len() == 2);

            edit_group(
                &client,
                &group.id,
                EditGroup {
                    name: Some("test-group-edited".to_string()),
                    owner: Some(user_a_id.clone()),
                },
            )
            .await
            .unwrap();

            let fetched_group = fetch_group(&client, &group.id).await.unwrap();
            assert!(fetched_group.owner == user_a_id);
            assert!(fetched_group.members.len() == 2);

            assert!(
                edit_group(
                    &client,
                    &group.id,
                    EditGroup {
                        name: Some("this-doesn't-work".to_string()),
                        owner: None
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            add_group_user(&user_a, &group.id, &user_b_id)
                .await
                .unwrap();
            join_group(&user_b, &group.id).await.unwrap();
            refresh(&mut user_b).await.unwrap();

            leave_group(&user_b, &group.id).await.unwrap();
            refresh(&mut user_b).await.unwrap();
            assert!(
                leave_group(&user_b, &group.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            remove_group(&user_a, &group.id).await.unwrap();

            assert!(
                auth_ping(&client)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED))
            );

            assert!(
                auth_ping(&user_a)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED))
            );

            refresh(&mut client).await.unwrap();

            assert!(
                fetch_group(&client, &group.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_group_errors() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();
        sim.group_users("test-group", 0, vec![1]);

        sim.client("client", async move {
            let (client, client_id) = get_client(0, false).await.unwrap();
            let (user_a, user_a_id) = get_client(1, false).await.unwrap();

            let group_id = client.get_groups()[0].clone();

            assert!(
                add_group(
                    &client,
                    AddGroup {
                        name: "<script>alert('xss')</script>".to_string()
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                join_group(&user_a, &group_id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            assert!(
                edit_group(
                    &client,
                    &group_id,
                    EditGroup {
                        name: None,
                        owner: Some(client_id.clone())
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );
            assert!(
                edit_group(
                    &client,
                    &group_id,
                    EditGroup {
                        name: None,
                        owner: Some("abc".to_string())
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );
            assert!(
                edit_group(
                    &client,
                    &group_id,
                    EditGroup {
                        name: Some("<script>alert('xss')</script>".to_string()),
                        owner: None
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                remove_group(&client, "abc")
                    .await
                    .is_err_and(|e| { e.status() == Some(StatusCode::NOT_FOUND) })
            );

            assert!(
                add_group_user(&client, "abc", &user_a_id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );
            assert!(
                add_group_user(&client, &group_id, "abc")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            assert!(
                add_group_user(&client, &group_id, &user_a_id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                remove_group_user(&client, &group_id, &client_id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                remove_group_user(&client, "abc", &user_a_id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );
            assert!(
                remove_group_user(&client, &group_id, "abc")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            Ok(())
        });

        sim.run()
    })
}
