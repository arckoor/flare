use std::collections::HashSet;

use flare::api::api_params::AddPoll;
use flare_sim::{
    helpers::{
        add_image, add_poll, fetch_image, fetch_poll, fetch_voting_image, get_client, jpg_images,
        login, logins, logout, png_images, post, remove_image, upload_all_pngs,
    },
    test_builder::flare_test,
    turmoil,
};
use reqwest::StatusCode;

#[test]
fn test_add_image() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;
            let other_client = get_client(1).await.0;

            let image = png_images()[0];

            let uploaded_image = add_image(&client, image, "image/png").await.unwrap();

            let fetched_image = fetch_image(&client, &uploaded_image.name).await.unwrap();

            assert_eq!(image, fetched_image);

            assert!(
                fetch_image(&client, "test")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            // not setting a mime type
            let part = reqwest::multipart::Part::bytes(image).file_name("image.png");
            let form = reqwest::multipart::Form::new().part("image", part);

            assert!(
                post(&client, "/api/image")
                    .multipart(form)
                    .send()
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // empty form
            let form = reqwest::multipart::Form::new();

            assert!(
                post(&client, "/api/image")
                    .multipart(form)
                    .send()
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            let bad_part = reqwest::multipart::Part::bytes((0..=255).collect::<Vec<_>>());
            let form = reqwest::multipart::Form::new().part("image", bad_part);
            assert!(
                post(&client, "/api/image")
                    .multipart(form)
                    .send()
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // no form at all
            assert!(
                post(&client, "/api/image")
                    .send()
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                add_image(&client, image, "image/jpeg")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                add_image(&client, image, "application/json")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                fetch_image(&other_client, &uploaded_image.name)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            for (image, mime) in png_images()
                .into_iter()
                .map(|i| (i, "image/png"))
                .chain(jpg_images().into_iter().map(|i| (i, "image/jpeg")))
            {
                let uploaded = add_image(&client, image, mime).await.unwrap();
                assert_eq!(fetch_image(&client, &uploaded.name).await.unwrap(), image);
            }

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_remove_image() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let mut client = get_client(0).await.0;

            let images = upload_all_pngs(&client).await;

            logout(&mut client).await.unwrap();
            login(&mut client, &logins()[1]).await.unwrap();

            for image in images.iter() {
                assert!(
                    remove_image(&client, &image)
                        .await
                        .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
                );
            }

            logout(&mut client).await.unwrap();
            login(&mut client, &logins()[0]).await.unwrap();

            for image in images.iter() {
                assert!(remove_image(&client, &image).await.is_ok());
            }

            for image in images.iter() {
                assert!(
                    remove_image(&client, &image)
                        .await
                        .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
                );
            }

            let images = upload_all_pngs(&client).await;

            add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "testing poll".to_string(),
                    ends: f64::MAX,
                    images: HashSet::from_iter(images.iter().cloned()),
                    voting_limit: 2,
                    group: None,
                },
            )
            .await
            .unwrap();

            for image in images.iter() {
                assert!(
                    remove_image(&client, &image)
                        .await
                        .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
                );
            }

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_fetch_invalid_image() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;

            assert!(
                fetch_image(&client, "nonexistant.png")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            assert!(
                fetch_image(&client, "non-existant.png")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                fetch_image(&client, "..%2FCargo.toml")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                fetch_image(&client, "foo%2Fbar.png")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                fetch_image(&client, "&foo.png")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_aspect_ratio() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;

            let img_16x9 = png_images()[0];
            let img_1x1 = png_images()[1];

            let id_16x9 = add_image(&client, img_16x9, "image/png")
                .await
                .unwrap()
                .name;

            let id_1x1 = add_image(&client, img_1x1, "image/png").await.unwrap().name;

            let poll = add_poll(
                &client,
                AddPoll {
                    title: "poll".to_string(),
                    info: "some info text".to_string(),
                    ends: f64::MAX,
                    images: [id_16x9.clone(), id_1x1.clone()].into(),
                    voting_limit: 1,
                    group: None,
                },
            )
            .await
            .unwrap();

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();

            assert_eq!(fetched_poll.aspect_ratios.get(&id_16x9).unwrap(), "16/9");
            assert_eq!(fetched_poll.aspect_ratios.get(&id_1x1).unwrap(), "1/1");

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_voting_image() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;

            let images = upload_all_pngs(&client).await;

            add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "test".to_string(),
                    ends: f64::MAX,
                    voting_limit: 3,
                    images: HashSet::from_iter(images.iter().cloned()),
                    group: None,
                },
            )
            .await
            .unwrap();

            for image in images.iter() {
                assert_eq!(
                    fetch_image(&client, &image).await.unwrap(),
                    fetch_voting_image(&client, &image).await.unwrap()
                )
            }

            assert!(
                fetch_voting_image(&client, "nonexistant.png")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_group_image() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();
        sim.group_users("sharing-images", 0, vec![1]);

        sim.client("client", async move {
            let client = get_client(0).await.0;
            let other_client = get_client(1).await.0;

            let images = upload_all_pngs(&client).await;

            for image in images.iter() {
                assert!(fetch_image(&client, image).await.is_ok());
                assert!(
                    fetch_image(&other_client, image)
                        .await
                        .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
                );
            }

            add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "i belong to a group!".to_string(),
                    ends: f64::MAX,
                    images: HashSet::from_iter(images.iter().cloned()),
                    voting_limit: 2,
                    group: Some(client.get_groups()[0].parse().unwrap()),
                },
            )
            .await
            .unwrap();

            for image in images.iter() {
                let client_image = fetch_image(&client, image).await.unwrap();
                let other_client_image = fetch_image(&other_client, image).await.unwrap();
                assert_eq!(client_image, other_client_image);
            }

            Ok(())
        });

        sim.run()
    })
}
