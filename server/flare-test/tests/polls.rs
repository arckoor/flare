use flare::api::api_params::{AddPoll, EditPoll, Paginator, PublishResults, Vote};
use flare_sim::{
    helpers::{
        add_image, add_poll, edit_poll, fetch_poll, fetch_polls, fetch_results, fetch_vote,
        fetch_voting_poll, fetch_voting_results, get_client, get_default_client, login, logins,
        logout, png_images, publish_results, remove_poll, vote,
    },
    test_builder::flare_test,
    turmoil,
};
use reqwest::StatusCode;

#[test]
fn test_add_remove_poll() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let mut client = get_default_client().await.unwrap();

            let mut images = Vec::new();
            for (image, mime) in png_images().into_iter().map(|i| (i, "image/png")) {
                let uploaded = add_image(&client, image.to_vec(), mime)
                    .await
                    .unwrap()
                    .name
                    .to_string();

                images.push(uploaded);
            }

            let mut invalid_poll = AddPoll {
                title: "foo".to_string(),
                info: "bar".to_string(),
                ends: f64::MAX,
                images: vec![],
                allowed_votes: 1,
            };

            // no images
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            invalid_poll.images = vec![images[0].clone()];

            // only a single image
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            invalid_poll.images = images.iter().map(|i| i.to_string()).collect();
            invalid_poll.allowed_votes = 0;

            // no votes
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            invalid_poll.allowed_votes = images.len() as u32 + 1;

            // too many votes
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            invalid_poll.allowed_votes = u32::MAX;

            // internally it's an i32, so 32::MAX is too big
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            let poll = add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "some test poll".to_string(),
                    ends: f64::MAX,
                    images: images.iter().skip(1).map(|i| i.to_string()).collect(),
                    allowed_votes: 2,
                },
            )
            .await
            .unwrap();

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            assert_eq!(fetched_poll.id, poll.id);
            assert_eq!(fetched_poll.title, "test");
            assert_eq!(fetched_poll.ends, f64::MAX);
            assert_eq!(fetched_poll.votes, 0);
            fetched_poll
                .images
                .iter()
                .zip(images.iter().skip(1))
                .for_each(|(f, i)| {
                    assert_eq!(f, i);
                });

            assert!(
                add_poll(
                    &client,
                    AddPoll {
                        title: "reused image".to_string(),
                        info: "more testing".to_string(),
                        ends: f64::MAX,
                        images: images.iter().map(|i| i.to_string()).collect(),
                        allowed_votes: 2,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            logout(&mut client).await.unwrap();
            login(&mut client, &logins()[1]).await.unwrap();

            assert!(
                add_poll(
                    &client,
                    AddPoll {
                        title: "test".to_string(),
                        info: "some test poll".to_string(),
                        ends: f64::MAX,
                        images: vec![images[0].clone()],
                        allowed_votes: 1,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                remove_poll(&client, &poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            logout(&mut client).await.unwrap();
            login(&mut client, &logins()[0]).await.unwrap();

            remove_poll(&client, &poll.id).await.unwrap();

            assert!(
                fetch_poll(&client, &poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_fetch_polls() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let mut client = get_default_client().await.unwrap();

            let polls = fetch_polls(&client, None).await.unwrap();

            assert_eq!(polls.page, 0);
            assert_eq!(polls.page_count, 0);
            assert!(polls.polls.is_empty());

            assert!(
                fetch_polls(
                    &client,
                    Some(Paginator {
                        page: 1,
                        page_size: 20,
                        asc: true
                    })
                )
                .await
                .is_ok_and(|p| p.polls.is_empty())
            );

            assert!(
                fetch_polls(
                    &client,
                    Some(Paginator {
                        page: 0,
                        page_size: 0,
                        asc: true
                    })
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                fetch_polls(
                    &client,
                    Some(Paginator {
                        page: 0,
                        page_size: 200,
                        asc: true
                    })
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                fetch_poll(&client, "foo")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            assert!(
                fetch_poll(&client, "")
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            let mut images = Vec::new();

            for (image, mime) in png_images().into_iter().map(|i| (i, "image/png")) {
                let uploaded = add_image(&client, image.to_vec(), mime)
                    .await
                    .unwrap()
                    .name
                    .to_string();

                images.push(uploaded);
            }

            let mut polls = Vec::new();

            for images in images.chunks_exact(3) {
                let poll = add_poll(
                    &client,
                    AddPoll {
                        title: "test".to_string(),
                        info: "some test poll".to_string(),
                        ends: f64::MAX,
                        images: images.iter().map(|i| i.to_string()).collect(),
                        allowed_votes: 2,
                    },
                )
                .await
                .unwrap();

                polls.push(poll.id.clone());

                let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();

                assert_eq!(fetched_poll.id, poll.id);
                assert_eq!(fetched_poll.title, "test");
                assert_eq!(fetched_poll.ends, f64::MAX);
                assert_eq!(fetched_poll.votes, 0);
                fetched_poll
                    .images
                    .iter()
                    .zip(images.iter())
                    .for_each(|(f, i)| {
                        assert_eq!(f, i);
                    });
            }

            let fetched_polls = fetch_polls(&client, None).await.unwrap();
            assert_eq!(fetched_polls.polls.len(), polls.len());
            assert_eq!(fetched_polls.page_count, 1);
            assert_eq!(fetched_polls.page, 0);

            let paged_polls = fetch_polls(
                &client,
                Some(Paginator {
                    page: 1,
                    page_size: 2,
                    asc: true,
                }),
            )
            .await
            .unwrap();

            assert_eq!(paged_polls.polls.len(), 1);
            assert_eq!(paged_polls.page_count, 2);
            assert_eq!(paged_polls.polls[0].id, polls[2]);

            let paged_polls = fetch_polls(
                &client,
                Some(Paginator {
                    page: 0,
                    page_size: 3,
                    asc: true,
                }),
            )
            .await
            .unwrap();
            assert_eq!(paged_polls.polls.len(), 3);
            assert_eq!(paged_polls.page_count, 1);

            let reversed_polls = fetch_polls(
                &client,
                Some(Paginator {
                    page: 0,
                    page_size: 3,
                    asc: false,
                }),
            )
            .await
            .unwrap();

            for (i, poll) in paged_polls.polls.iter().rev().enumerate() {
                assert_eq!(poll.id, reversed_polls.polls[i].id);
                assert_eq!(poll.ends, reversed_polls.polls[i].ends);
                assert_eq!(poll.title, reversed_polls.polls[i].title);
            }

            logout(&mut client).await.unwrap();
            login(&mut client, &logins()[1]).await.unwrap();

            assert!(
                fetch_polls(&client, None)
                    .await
                    .is_ok_and(|p| p.polls.is_empty())
            );

            for id in polls.iter() {
                assert!(
                    fetch_poll(&client, id)
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
fn test_edit_poll() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_default_client().await.unwrap();
            let mut initial_images = Vec::new();
            let mut add_images = Vec::new();

            for (idx, image) in png_images().iter().take(5).enumerate() {
                let uploaded = add_image(&client, image.to_vec(), "image/png")
                    .await
                    .unwrap()
                    .name
                    .to_string();

                if idx < 3 {
                    initial_images.push(uploaded);
                } else {
                    add_images.push(uploaded);
                }
            }

            let mut title = "Poll that will be edited".to_string();

            let poll = add_poll(
                &client,
                AddPoll {
                    title: title.clone(),
                    info: "editing c:".to_string(),
                    ends: 0.0,
                    images: initial_images.clone(),
                    allowed_votes: 1,
                },
            )
            .await
            .unwrap();

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            assert_eq!(fetched_poll.images.len(), initial_images.len());
            assert_eq!(fetched_poll.title, title);
            assert!(
                fetched_poll
                    .images
                    .iter()
                    .all(|i| initial_images.contains(i))
            );

            title = "Edited poll".to_string();

            edit_poll(
                &client,
                &poll.id,
                EditPoll {
                    title: Some(title.clone()),
                    add_images: Some(add_images.clone()),
                    remove_images: Some(vec![initial_images[0].clone()]),
                    info: None,
                    ends: None,
                    allowed_votes: None,
                },
            )
            .await
            .unwrap();

            let mut current_images = fetched_poll
                .images
                .iter()
                .skip(1)
                .cloned()
                .collect::<Vec<_>>();

            current_images.append(&mut add_images.clone());

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            assert_eq!(fetched_poll.images.len(), current_images.len());
            assert_eq!(fetched_poll.title, title);
            assert!(
                fetched_poll
                    .images
                    .iter()
                    .all(|i| current_images.contains(i))
            );

            assert!(
                edit_poll(
                    &client,
                    &poll.id.clone(),
                    EditPoll {
                        title: None,
                        info: None,
                        ends: None,
                        allowed_votes: None,
                        add_images: None,
                        remove_images: Some(current_images.clone())
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                edit_poll(
                    &client,
                    &poll.id.clone(),
                    EditPoll {
                        title: None,
                        info: None,
                        ends: None,
                        allowed_votes: None,
                        add_images: None,
                        remove_images: Some(current_images.iter().skip(1).cloned().collect())
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                edit_poll(
                    &client,
                    &poll.id.clone(),
                    EditPoll {
                        title: None,
                        info: None,
                        ends: None,
                        allowed_votes: None,
                        add_images: Some(current_images.clone()),
                        remove_images: None,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_poll_text_validation() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_default_client().await.unwrap();

            assert!(
                add_poll(
                    &client,
                    AddPoll {
                        title: "Friendly poll".to_string(),
                        info: "<script>alert('xss')</script>".to_string(),
                        ends: 0.0,
                        images: vec![],
                        allowed_votes: 1,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                add_poll(
                    &client,
                    AddPoll {
                        title: "<script>alert('xss')</script>".to_string(),
                        info: "Very friendly poll, nothing to worry about here :)".to_string(),
                        ends: 0.0,
                        images: vec![],
                        allowed_votes: 1,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            let mut images = Vec::new();

            for image in png_images().iter().take(5) {
                let uploaded = add_image(&client, image.to_vec(), "image/png")
                    .await
                    .unwrap()
                    .name
                    .to_string();

                images.push(uploaded);
            }

            let poll = add_poll(
                &client,
                AddPoll {
                    title: "Friendly poll".to_string(),
                    info: "Very friendly poll, nothing to worry about here :)".to_string(),
                    ends: 0.0,
                    images: images.clone(),
                    allowed_votes: 1,
                },
            )
            .await
            .unwrap();

            assert!(
                edit_poll(
                    &client,
                    &poll.id,
                    EditPoll {
                        title: Some("<script>alert('xss')</script>".to_string()),
                        info: None,
                        ends: None,
                        allowed_votes: None,
                        add_images: None,
                        remove_images: None,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                edit_poll(
                    &client,
                    &poll.id,
                    EditPoll {
                        title: None,
                        info: Some("<script>alert('xss')</script>".to_string()),
                        ends: None,
                        allowed_votes: None,
                        add_images: None,
                        remove_images: None,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            assert_eq!(fetched_poll.title, "Friendly poll");
            assert_eq!(
                fetched_poll.info,
                "Very friendly poll, nothing to worry about here :)"
            );
            assert_eq!(fetched_poll.votes, 0);
            assert_eq!(fetched_poll.images.len(), images.len());

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_voting() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_default_client().await.unwrap();
            let voter = get_client(1, true).await.unwrap().0;

            let mut images = Vec::new();
            for (image, mime) in png_images().into_iter().map(|i| (i, "image/png")) {
                let uploaded = add_image(&client, image.to_vec(), mime)
                    .await
                    .unwrap()
                    .name
                    .to_string();

                images.push(uploaded);
            }

            let old_poll = add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "some test poll".to_string(),
                    ends: 0.0,
                    images: vec![images[0].clone(), images[1].clone()],
                    allowed_votes: 2,
                },
            )
            .await
            .unwrap();

            assert!(
                vote(
                    &voter,
                    &old_poll.id,
                    Vote {
                        votes: vec![images[0].clone(), images[1].clone()],
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            remove_poll(&client, &old_poll.id).await.unwrap();

            let images = images.into_iter().skip(2).collect::<Vec<_>>();

            let poll = add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "some test poll".to_string(),
                    ends: f64::MAX,
                    images: images.iter().map(|i| i.to_string()).collect(),
                    allowed_votes: 2,
                },
            )
            .await
            .unwrap();

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            let voting_poll = fetch_voting_poll(&voter, &poll.id).await.unwrap();

            assert_eq!(fetched_poll.id, voting_poll.id);
            assert_eq!(fetched_poll.title, voting_poll.title);
            assert_eq!(fetched_poll.ends, voting_poll.ends);
            assert_eq!(fetched_poll.images.len(), voting_poll.images.len());
            for image in voting_poll.images.iter() {
                assert!(fetched_poll.images.contains(image));
            }

            assert!(
                vote(
                    &voter,
                    "abc",
                    Vote {
                        votes: vec![images[0].clone()],
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            assert!(
                vote(
                    &voter,
                    &poll.id,
                    Vote {
                        votes: vec![images[0].clone(), images[1].clone(), images[2].clone()],
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                vote(&voter, &poll.id, Vote { votes: vec![] })
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            vote(
                &voter,
                &poll.id,
                Vote {
                    votes: vec![images[0].clone(), images[1].clone(), images[1].clone()],
                    // voting twice for the same image is ignored
                },
            )
            .await
            .unwrap();

            let actual_vote = fetch_vote(&voter, &poll.id).await.unwrap();
            assert_eq!(actual_vote.votes.len(), 2);
            assert!(actual_vote.votes.contains(&images[0]));
            assert!(actual_vote.votes.contains(&images[1]));

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            assert_eq!(fetched_poll.votes, 2);

            let fetched_vote = fetch_vote(&voter, &poll.id).await.unwrap();
            assert_eq!(fetched_vote.votes.len(), 2);
            assert!(fetched_vote.votes.contains(&images[0]));
            assert!(fetched_vote.votes.contains(&images[1]));

            assert!(
                vote(
                    &voter,
                    &poll.id,
                    Vote {
                        votes: vec![images[0].clone(), images[1].clone()],
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // we ditch the cookies, but we still have the same ip
            let voter = get_client(1, true).await.unwrap().0;

            assert!(
                vote(
                    &voter,
                    &poll.id,
                    Vote {
                        votes: vec![images[0].clone()]
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // we are someone completely else, so we can vote
            let voter = get_client(2, true).await.unwrap().0;

            vote(
                &voter,
                &poll.id,
                Vote {
                    votes: vec![images[0].clone()],
                },
            )
            .await
            .unwrap();

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            assert_eq!(fetched_poll.votes, 3);

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_results() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_default_client().await.unwrap();
            let voter_1 = get_client(1, true).await.unwrap().0;
            let voter_2 = get_client(2, true).await.unwrap().0;
            let voter_3 = get_client(3, true).await.unwrap().0;

            let mut images = Vec::new();
            for (image, mime) in png_images().into_iter().map(|i| (i, "image/png")) {
                let uploaded = add_image(&client, image.to_vec(), mime)
                    .await
                    .unwrap()
                    .name
                    .to_string();

                images.push(uploaded);
            }

            let poll = add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "some test poll".to_string(),
                    ends: f64::MAX,
                    images: images.iter().map(|i| i.to_string()).collect(),
                    allowed_votes: 3,
                },
            )
            .await
            .unwrap();

            vote(
                &voter_1,
                &poll.id,
                Vote {
                    votes: vec![images[0].clone(), images[1].clone(), images[2].clone()],
                },
            )
            .await
            .unwrap();
            vote(
                &voter_2,
                &poll.id,
                Vote {
                    votes: vec![images[1].clone(), images[2].clone()],
                },
            )
            .await
            .unwrap();
            vote(
                &voter_3,
                &poll.id,
                Vote {
                    votes: vec![images[2].clone()],
                },
            )
            .await
            .unwrap();

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            assert_eq!(fetched_poll.votes, 6);

            let results = fetch_results(&client, &poll.id).await.unwrap();
            assert!(results.ended == false);
            assert!(results.public == false);

            assert!(
                fetch_voting_results(&voter_1, &poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            edit_poll(
                &client,
                &poll.id,
                EditPoll {
                    title: None,
                    info: None,
                    ends: Some(0.0),
                    allowed_votes: None,
                    add_images: None,
                    remove_images: None,
                },
            )
            .await
            .unwrap();

            publish_results(&client, &poll.id, PublishResults { published: true })
                .await
                .unwrap();
            assert!(
                publish_results(&client, &poll.id, PublishResults { published: true })
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );
            let results = fetch_results(&client, &poll.id).await.unwrap();
            assert!(results.ended == true);
            assert!(results.public == true);
            assert_eq!(results.votes.len(), images.len());
            assert_eq!(*results.votes.get(images[0].as_str()).unwrap(), 1);
            assert_eq!(*results.votes.get(images[1].as_str()).unwrap(), 2);
            assert_eq!(*results.votes.get(images[2].as_str()).unwrap(), 3);

            let fetched_results = fetch_voting_results(&voter_1, &poll.id).await.unwrap();
            assert_eq!(fetched_results.first, images[2]);
            assert_eq!(fetched_results.second, images[1]);
            assert_eq!(fetched_results.third, Some(images[0].clone()));
            for image in images.iter().skip(3) {
                assert!(fetched_results.remaining.contains(image));
            }

            publish_results(&client, &poll.id, PublishResults { published: false })
                .await
                .unwrap();

            let results = fetch_results(&client, &poll.id).await.unwrap();
            assert!(results.public == false);

            assert!(
                fetch_voting_results(&voter_1, &poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_group_poll() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();
        sim.group_users("test-group", 0, vec![1, 2]);

        sim.client("client", async move {
            // TODO
            // 0 creates a poll in the group, adds some of their own images to it
            // 1 and 2 should be able to fetch the images, and the poll
            // 1 and 2 should also be able to remove images from the poll, but calling remove directly on 0's images should not work
            // adding their own images should work
            // 1 or 2 should be able to remove the poll

            Ok(())
        });

        sim.run()
    })
}
