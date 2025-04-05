use flare::api::api_params::AddPoll;
use flare_sim::{
    helpers::{
        add_image, add_poll, fetch_image, fetch_voting_image, get_default_client, jpg_images,
        login, logins, logout, png_images, post, remove_image,
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
            let mut client = get_default_client().await.unwrap();

            let image = png_images()[0];

            let uploaded_image = add_image(&client, image.to_vec(), "image/png")
                .await
                .unwrap();

            let fetched_image = fetch_image(&client, &uploaded_image.name).await.unwrap();

            assert_eq!(image.to_vec(), fetched_image);

            assert!(
                fetch_image(&client, "test")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            // not setting a mime type
            let part = reqwest::multipart::Part::bytes(image.to_vec()).file_name("image.png");
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
                add_image(&client, image.to_vec(), "image/jpeg")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                add_image(&client, image.to_vec(), "application/json")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            logout(&mut client).await.unwrap();
            login(&mut client, &logins()[1]).await.unwrap();

            assert!(
                fetch_image(&client, &uploaded_image.name)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );

            logout(&mut client).await.unwrap();

            client.bearer = Some("invalid".to_string());

            assert!(
                fetch_image(&client, &uploaded_image.name)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::UNAUTHORIZED))
            );

            login(&mut client, &logins()[0]).await.unwrap();
            for (image, mime) in png_images()
                .into_iter()
                .skip(1)
                .map(|i| (i, "image/png"))
                .chain(jpg_images().into_iter().map(|i| (i, "image/jpeg")))
            {
                let uploaded = add_image(&client, image.to_vec(), mime).await.unwrap();
                assert_eq!(
                    fetch_image(&client, &uploaded.name).await.unwrap(),
                    image.to_vec()
                );
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
            let mut client = get_default_client().await.unwrap();

            let mut images = Vec::new();
            for (image, mime) in png_images().into_iter().map(|i| (i, "image/png")) {
                let uploaded = add_image(&client, image.to_vec(), mime).await.unwrap();
                images.push(uploaded.name.clone());
            }

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
            let client = get_default_client().await.unwrap();

            assert!(
                fetch_image(&client, "non-existant.png")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
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
fn test_voting_image() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_default_client().await.unwrap();

            let mut images = Vec::new();
            for (image, mime) in png_images().into_iter().map(|i| (i, "image/png")) {
                let uploaded = add_image(&client, image.to_vec(), mime)
                    .await
                    .unwrap()
                    .name
                    .to_string();

                images.push(uploaded);
            }

            add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "test".to_string(),
                    ends: f64::MAX,
                    allowed_votes: 3,
                    images: images.clone(),
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
                fetch_voting_image(&client, "non-existant.png")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            Ok(())
        });

        sim.run()
    })
}
