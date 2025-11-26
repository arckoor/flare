use std::collections::HashSet;

use flare::api::{
    api_params::{AddPoll, EditPoll, FetchPollSort, Paginator, PublishResults, UpdatedPoll, Vote},
    middleware::TRACING_TOKEN,
};
use flare_sim::{
    helpers::{
        add_image, add_poll, add_poll_to_group, edit_poll, fetch_image, fetch_poll, fetch_polls,
        fetch_results, fetch_vote, fetch_voting_poll, fetch_voting_results, get_client, login,
        logins, logout, png_images, publish_results, remove_group, remove_image, remove_poll,
        upload_all_pngs, upload_many_pngs, vote,
    },
    test_builder::flare_test,
    turmoil,
};
use reqwest::StatusCode;

#[test]
fn test_poll_add_remove() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;
            let other_client = get_client(1).await.0;

            let images = upload_all_pngs(&client).await;

            let mut invalid_poll = AddPoll {
                title: "foo".to_string(),
                info: "bar".to_string(),
                ends: f64::MAX,
                images: [].into(),
                voting_limit: 1,
                group: None,
            };

            // no images
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            invalid_poll.images = [images[0].clone()].into();

            // only a single image
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            invalid_poll.images = images.iter().map(|i| i.to_string()).collect();
            invalid_poll.voting_limit = 0;

            // no votes
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            invalid_poll.voting_limit = images.len() as u32 + 1;

            // too many votes
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            invalid_poll.voting_limit = u32::MAX;

            // internally it's an i32, so 32::MAX is too big
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            invalid_poll.voting_limit = 2;
            invalid_poll.group = Some("abc".parse().unwrap());

            // adding to a poll that doesn't exist / we're not a part of
            assert!(
                add_poll(&client, invalid_poll.clone())
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            let poll = add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "some test poll".to_string(),
                    ends: f64::MAX,
                    images: images.iter().skip(1).map(|i| i.to_string()).collect(),
                    voting_limit: 2,
                    group: None,
                },
            )
            .await
            .unwrap();

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            assert_eq!(fetched_poll.id, poll.id);
            assert_eq!(fetched_poll.title, "test");
            assert_eq!(fetched_poll.ends, f64::MAX);
            assert_eq!(fetched_poll.votes, 0);
            assert_eq!(fetched_poll.group, None);
            for image in fetched_poll.images.iter() {
                assert!(images.iter().skip(1).any(|i| i == image));
            }

            assert!(
                add_poll(
                    &client,
                    AddPoll {
                        title: "reused image".to_string(),
                        info: "more testing".to_string(),
                        ends: f64::MAX,
                        images: images.iter().map(|i| i.to_string()).collect(),
                        voting_limit: 2,
                        group: None,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // the image isn't used, but it doesn't belong to this user
            assert!(
                add_poll(
                    &other_client,
                    AddPoll {
                        title: "test".to_string(),
                        info: "some test poll".to_string(),
                        ends: f64::MAX,
                        images: [images[0].clone()].into(),
                        voting_limit: 1,
                        group: None,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                remove_poll(&other_client, &poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

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
fn test_polls_fetch() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let mut client = get_client(0).await.0;

            let polls = fetch_polls(&client, None, None).await.unwrap();

            assert_eq!(polls.page, 0);
            assert_eq!(polls.page_count, 0);
            assert!(polls.polls.is_empty());

            assert!(
                fetch_polls(
                    &client,
                    None,
                    Some(Paginator {
                        page: 1,
                        page_size: 20,
                        asc: true,
                        sort_by: None,
                    })
                )
                .await
                .is_ok_and(|p| p.polls.is_empty())
            );

            assert!(
                fetch_polls(
                    &client,
                    None,
                    Some(Paginator {
                        page: 0,
                        page_size: 0,
                        asc: true,
                        sort_by: None,
                    })
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            assert!(
                fetch_polls(
                    &client,
                    None,
                    Some(Paginator {
                        page: 0,
                        page_size: 200,
                        asc: true,
                        sort_by: None,
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

            let images = upload_all_pngs(&client).await;

            let mut polls = Vec::new();

            for (i, images) in images.chunks_exact(3).enumerate() {
                let (name, ends) = match i {
                    0 => ("aaaaaaa-poll", f64::MAX - 1.0),
                    1 => ("fffffff-poll", f64::MAX - 2.0),
                    2 => ("zzzzzzz-poll", f64::MAX - 3.0),
                    _ => unreachable!(),
                };

                let poll = add_poll(
                    &client,
                    AddPoll {
                        title: name.to_string(),
                        info: "some test poll".to_string(),
                        ends,
                        images: images.iter().map(|i| i.to_string()).collect(),
                        voting_limit: 2,
                        group: None,
                    },
                )
                .await
                .unwrap();

                polls.push(poll.id.clone());

                let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();

                assert_eq!(fetched_poll.id, poll.id);
                assert_eq!(fetched_poll.title, name);
                assert_eq!(fetched_poll.ends, ends);
                assert_eq!(fetched_poll.votes, 0);
                for image in images.iter() {
                    assert!(fetched_poll.images.contains(image));
                }
            }

            let fetched_polls = fetch_polls(&client, None, None).await.unwrap();
            assert_eq!(fetched_polls.polls.len(), polls.len());
            assert_eq!(fetched_polls.page_count, 1);
            assert_eq!(fetched_polls.page, 0);

            let paged_polls = fetch_polls(
                &client,
                None,
                Some(Paginator {
                    page: 1,
                    page_size: 2,
                    asc: true,
                    sort_by: None,
                }),
            )
            .await
            .unwrap();

            assert_eq!(paged_polls.polls.len(), 1);
            assert_eq!(paged_polls.page_count, 2);
            assert_eq!(paged_polls.polls[0].id, polls[2]);

            let paged_polls = fetch_polls(
                &client,
                None,
                Some(Paginator {
                    page: 0,
                    page_size: 3,
                    asc: true,
                    sort_by: None,
                }),
            )
            .await
            .unwrap();
            assert_eq!(paged_polls.polls.len(), 3);
            assert_eq!(paged_polls.page_count, 1);

            let reversed_polls = fetch_polls(
                &client,
                None,
                Some(Paginator {
                    page: 0,
                    page_size: 3,
                    asc: false,
                    sort_by: None,
                }),
            )
            .await
            .unwrap();

            for (i, poll) in paged_polls.polls.iter().rev().enumerate() {
                assert_eq!(poll.id, reversed_polls.polls[i].id);
                assert_eq!(poll.ends, reversed_polls.polls[i].ends);
                assert_eq!(poll.title, reversed_polls.polls[i].title);
            }

            let sorted_by_title = fetch_polls(
                &client,
                None,
                Some(Paginator {
                    page: 0,
                    page_size: 3,
                    asc: true,
                    sort_by: Some(FetchPollSort::Title),
                }),
            )
            .await
            .unwrap();

            assert_eq!(sorted_by_title.polls[0].title, "aaaaaaa-poll");
            assert_eq!(sorted_by_title.polls[1].title, "fffffff-poll");
            assert_eq!(sorted_by_title.polls[2].title, "zzzzzzz-poll");

            let sorted_by_title = fetch_polls(
                &client,
                None,
                Some(Paginator {
                    page: 0,
                    page_size: 3,
                    asc: false,
                    sort_by: Some(FetchPollSort::Ends),
                }),
            )
            .await
            .unwrap();

            assert_eq!(sorted_by_title.polls[0].ends, f64::MAX - 1.0);
            assert_eq!(sorted_by_title.polls[1].ends, f64::MAX - 2.0);
            assert_eq!(sorted_by_title.polls[2].ends, f64::MAX - 3.0);

            logout(&mut client).await.unwrap();
            login(&mut client, &logins()[1]).await.unwrap();

            assert!(
                fetch_polls(&client, None, None)
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
fn test_poll_edit() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;

            let initial_images = upload_many_pngs(&client, 0, 3).await;
            let add_images = upload_many_pngs(&client, 4, 6).await;

            let mut title = "Poll that will be edited".to_string();

            let poll = add_poll(
                &client,
                AddPoll {
                    title: title.clone(),
                    info: "editing c:".to_string(),
                    ends: 0.0,
                    images: initial_images.iter().cloned().collect(),
                    voting_limit: 1,
                    group: None,
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
                    add_images: Some(add_images.iter().cloned().collect()),
                    remove_images: Some([initial_images[0].clone()].into()),
                    info: None,
                    ends: None,
                    voting_limit: None,
                    updated_at: poll.updated_at,
                },
            )
            .await
            .unwrap();

            let mut current_images = fetched_poll
                .images
                .iter()
                .cloned()
                .filter(|i| *i != initial_images[0])
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

            // editing a modified poll
            assert!(
                edit_poll(
                    &client,
                    &poll.id.clone(),
                    EditPoll {
                        title: Some("test".to_string()),
                        info: None,
                        ends: None,
                        voting_limit: None,
                        add_images: None,
                        remove_images: None,
                        updated_at: poll.updated_at,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::CONFLICT))
            );

            // trying to remove all images
            assert!(
                edit_poll(
                    &client,
                    &poll.id.clone(),
                    EditPoll {
                        title: None,
                        info: None,
                        ends: None,
                        voting_limit: None,
                        add_images: None,
                        remove_images: Some(current_images.iter().cloned().collect()),
                        updated_at: poll.updated_at,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // trying to remove all but one image
            assert!(
                edit_poll(
                    &client,
                    &poll.id.clone(),
                    EditPoll {
                        title: None,
                        info: None,
                        ends: None,
                        voting_limit: None,
                        add_images: None,
                        remove_images: Some(current_images.iter().skip(1).cloned().collect()),
                        updated_at: poll.updated_at,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // trying to add already used images
            assert!(
                edit_poll(
                    &client,
                    &poll.id.clone(),
                    EditPoll {
                        title: None,
                        info: None,
                        ends: None,
                        voting_limit: None,
                        add_images: Some(current_images.iter().cloned().collect()),
                        remove_images: None,
                        updated_at: poll.updated_at,
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
            let client = get_client(0).await.0;

            assert!(
                add_poll(
                    &client,
                    AddPoll {
                        title: "Friendly poll".to_string(),
                        info: "<script>alert('xss')</script>".to_string(),
                        ends: 0.0,
                        images: [].into(),
                        voting_limit: 1,
                        group: None,
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
                        images: [].into(),
                        voting_limit: 1,
                        group: None,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            let images = upload_many_pngs(&client, 0, 5).await;

            let poll = add_poll(
                &client,
                AddPoll {
                    title: "Friendly poll".to_string(),
                    info: "Very friendly poll, nothing to worry about here :)".to_string(),
                    ends: 0.0,
                    images: HashSet::from_iter(images.iter().cloned()),
                    voting_limit: 1,
                    group: None,
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
                        voting_limit: None,
                        add_images: None,
                        remove_images: None,
                        updated_at: poll.updated_at,
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
                        voting_limit: None,
                        add_images: None,
                        remove_images: None,
                        updated_at: poll.updated_at,
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
            let client = get_client(0).await.0;
            let (mut voter, voter_id) = get_client(1).await;

            let images = upload_all_pngs(&client).await;

            let old_poll = add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "some test poll".to_string(),
                    ends: 0.0,
                    images: [images[0].clone(), images[1].clone()].into(),
                    voting_limit: 2,
                    group: None,
                },
            )
            .await
            .unwrap();

            // voting period already over
            assert!(
                vote(
                    &voter,
                    &old_poll.id,
                    Vote {
                        votes: [images[0].clone(), images[1].clone()].into(),
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
                    voting_limit: 2,
                    group: None,
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

            // poll doesn't exist
            assert!(
                vote(
                    &voter,
                    "abc",
                    Vote {
                        votes: [images[0].clone()].into(),
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            // too many votes
            assert!(
                vote(
                    &voter,
                    &poll.id,
                    Vote {
                        votes: [images[0].clone(), images[1].clone(), images[2].clone()].into(),
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // no votes
            assert!(
                vote(&voter, &poll.id, Vote { votes: [].into() })
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // this one works
            vote(
                &voter,
                &poll.id,
                Vote {
                    votes: [images[0].clone(), images[1].clone()].into(),
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

            // voting again
            assert!(
                vote(
                    &voter,
                    &poll.id,
                    Vote {
                        votes: [images[0].clone(), images[1].clone()].into(),
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // we change our ip, but we still have the same cookie
            voter.ip = "new-voter".to_string();
            assert!(
                vote(
                    &voter,
                    &poll.id,
                    Vote {
                        votes: [images[0].clone()].into()
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // resetting the ip back to the "normal" one
            voter.ip = voter_id;
            vote(
                &voter,
                &poll.id,
                Vote {
                    votes: [images[0].clone()].into(),
                },
            )
            .await
            .unwrap_err();

            let original_cookie = voter
                .cookie_store
                .lock()
                .unwrap()
                .iter_unexpired()
                .find(|x| x.name() == TRACING_TOKEN)
                .unwrap()
                .clone();

            // we ditch the cookies, but we still have the same ip
            let voter = get_client(1).await.0;

            assert!(
                vote(
                    &voter,
                    &poll.id,
                    Vote {
                        votes: [images[0].clone()].into()
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            // we ditched the cookie, but were still recognised by ip
            // but we should get a new cookie
            assert_ne!(
                &original_cookie,
                voter
                    .cookie_store
                    .lock()
                    .unwrap()
                    .iter_unexpired()
                    .find(|x| x.name() == TRACING_TOKEN)
                    .unwrap()
            );

            // we are someone completely else, so we can vote
            let voter = get_client(2).await.0;

            vote(
                &voter,
                &poll.id,
                Vote {
                    votes: [images[0].clone()].into(),
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
            let client = get_client(0).await.0;
            let voter_1 = get_client(1).await.0;
            let voter_2 = get_client(2).await.0;
            let voter_3 = get_client(3).await.0;
            let voter_4 = get_client(4).await.0;

            let images = upload_all_pngs(&client).await;

            let poll = add_poll(
                &client,
                AddPoll {
                    title: "test".to_string(),
                    info: "some test poll".to_string(),
                    ends: f64::MAX,
                    images: images.iter().map(|i| i.to_string()).collect(),
                    voting_limit: 4,
                    group: None,
                },
            )
            .await
            .unwrap();

            vote(
                &voter_1,
                &poll.id,
                Vote {
                    votes: [
                        images[0].clone(),
                        images[1].clone(),
                        images[2].clone(),
                        images[3].clone(),
                    ]
                    .into(),
                },
            )
            .await
            .unwrap();
            vote(
                &voter_2,
                &poll.id,
                Vote {
                    votes: [images[0].clone(), images[1].clone(), images[2].clone()].into(),
                },
            )
            .await
            .unwrap();
            vote(
                &voter_3,
                &poll.id,
                Vote {
                    votes: [images[0].clone(), images[1].clone()].into(),
                },
            )
            .await
            .unwrap();
            vote(
                &voter_4,
                &poll.id,
                Vote {
                    votes: [images[0].clone()].into(),
                },
            )
            .await
            .unwrap();

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            assert_eq!(fetched_poll.votes, 10);

            let results = fetch_results(&client, &poll.id).await.unwrap();
            assert!(results.ended == false);
            assert!(results.public == false);

            assert!(
                fetch_voting_results(&voter_1, &poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            let poll = edit_poll(
                &client,
                &poll.id,
                EditPoll {
                    title: None,
                    info: None,
                    ends: Some(0.0),
                    voting_limit: None,
                    add_images: None,
                    remove_images: None,
                    updated_at: poll.updated_at,
                },
            )
            .await
            .unwrap();

            let updated_poll = publish_results(
                &client,
                &poll.id,
                PublishResults {
                    published: true,
                    updated_at: poll.updated_at,
                },
            )
            .await
            .unwrap();

            let poll = fetch_poll(&client, &poll.id).await.unwrap();

            assert!(
                publish_results(
                    &client,
                    &poll.id,
                    PublishResults {
                        published: true,
                        updated_at: updated_poll.updated_at
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );
            let results = fetch_results(&client, &poll.id).await.unwrap();
            assert!(results.ended == true);
            assert!(results.public == true);
            assert_eq!(results.votes.len(), images.len());
            assert_eq!(*results.votes.get(images[0].as_str()).unwrap(), 4);
            assert_eq!(*results.votes.get(images[1].as_str()).unwrap(), 3);
            assert_eq!(*results.votes.get(images[2].as_str()).unwrap(), 2);
            assert_eq!(*results.votes.get(images[3].as_str()).unwrap(), 1);
            assert_eq!(*results.votes.get(images[4].as_str()).unwrap(), 0);

            let fetched_results = fetch_voting_results(&voter_1, &poll.id).await.unwrap();
            assert_eq!(fetched_results.first.len(), 1);
            assert_eq!(fetched_results.second.len(), 1);
            assert_eq!(fetched_results.third.len(), 1);

            assert_eq!(fetched_results.first[0], images[0]);
            assert_eq!(fetched_results.second[0], images[1]);
            assert_eq!(fetched_results.third[0], images[2].clone());
            for image in images.iter().skip(3) {
                assert!(fetched_results.remaining.contains(image));
            }

            publish_results(
                &client,
                &poll.id,
                PublishResults {
                    published: false,
                    updated_at: results.updated_at,
                },
            )
            .await
            .unwrap();

            let poll = fetch_poll(&client, &poll.id).await.unwrap();

            let results = fetch_results(&client, &poll.id).await.unwrap();
            assert!(results.public == false);

            assert!(
                fetch_voting_results(&voter_1, &poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::FORBIDDEN))
            );

            edit_poll(
                &client,
                &poll.id,
                EditPoll {
                    title: None,
                    info: None,
                    ends: None,
                    voting_limit: None,
                    add_images: None,
                    remove_images: Some([images[0].clone()].into()),
                    updated_at: poll.updated_at,
                },
            )
            .await
            .unwrap();

            let results = fetch_results(&client, &poll.id).await.unwrap();
            assert_eq!(results.votes.get(images[0].as_str()), None);
            assert_eq!(*results.votes.get(images[1].as_str()).unwrap(), 3);
            assert_eq!(*results.votes.get(images[2].as_str()).unwrap(), 2);
            assert_eq!(*results.votes.get(images[3].as_str()).unwrap(), 1);
            assert_eq!(*results.votes.get(images[4].as_str()).unwrap(), 0);

            remove_poll(&client, &poll.id).await.unwrap();

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_group_poll() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();
        sim.group_users("test-group", 0, vec![1]);

        sim.client("client", async move {
            let client = get_client(0).await.0;
            let user_a = get_client(1).await.0;
            let user_b = get_client(2).await.0;

            let images = upload_all_pngs(&client).await;

            let group_id = &client.get_groups()[0];

            let poll = add_poll(
                &client,
                AddPoll {
                    title: "group shared poll".to_string(),
                    info: "multiple users can access this".to_string(),
                    ends: f64::MAX,
                    images: images[..4].iter().cloned().collect(),
                    voting_limit: 2,
                    group: Some(group_id.parse().unwrap()),
                },
            )
            .await
            .unwrap();

            assert_eq!(
                fetch_polls(&client, None, None).await.unwrap().polls.len(),
                1
            );
            assert_eq!(
                fetch_polls(&client, Some(group_id.to_string()), None)
                    .await
                    .unwrap()
                    .polls
                    .len(),
                1
            );

            assert_eq!(
                fetch_polls(&user_b, None, None).await.unwrap().polls.len(),
                0
            );
            assert_eq!(
                fetch_polls(&user_b, Some(group_id.to_string()), None)
                    .await
                    .unwrap()
                    .polls
                    .len(),
                0
            );

            let client_fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            let user_a_fetched_poll = fetch_poll(&user_a, &poll.id).await.unwrap();
            assert_eq!(client_fetched_poll.title, user_a_fetched_poll.title);
            assert_eq!(client_fetched_poll.info, user_a_fetched_poll.info);
            assert_eq!(client_fetched_poll.ends, user_a_fetched_poll.ends);
            assert_eq!(
                client_fetched_poll.voting_limit,
                user_a_fetched_poll.voting_limit
            );
            assert_eq!(client_fetched_poll.group, user_a_fetched_poll.group);
            for img in &images[..4] {
                assert!(client_fetched_poll.images.contains(img));
                assert!(user_a_fetched_poll.images.contains(img));
                let client_img = fetch_image(&client, img).await.unwrap();
                let user_a_img = fetch_image(&user_a, img).await.unwrap();
                assert_eq!(client_img, user_a_img);
                assert!(
                    fetch_image(&user_b, img)
                        .await
                        .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
                );
            }

            assert!(
                edit_poll(
                    &user_a,
                    &poll.id,
                    EditPoll {
                        title: None,
                        info: None,
                        ends: None,
                        voting_limit: None,
                        add_images: Some([images[5].clone()].into()),
                        remove_images: None,
                        updated_at: poll.updated_at,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            let poll = edit_poll(
                &client,
                &poll.id,
                EditPoll {
                    title: None,
                    info: None,
                    ends: None,
                    voting_limit: None,
                    add_images: Some([images[5].clone()].into()),
                    remove_images: None,
                    updated_at: poll.updated_at,
                },
            )
            .await
            .unwrap();

            let user_a_img = add_image(&user_a, png_images()[0], "image/png")
                .await
                .unwrap()
                .name;

            assert!(
                edit_poll(
                    &user_a,
                    &poll.id,
                    EditPoll {
                        title: None,
                        info: None,
                        ends: None,
                        voting_limit: None,
                        add_images: Some([user_a_img.clone()].into()),
                        remove_images: Some([images[5].clone()].into()),
                        updated_at: poll.updated_at,
                    }
                )
                .await
                .is_ok()
            );

            assert!(
                remove_image(&user_a, &images[0])
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            let fetched_poll = fetch_poll(&client, &poll.id).await.unwrap();
            for img in [user_a_img].iter().chain(images[..4].iter()) {
                assert!(fetched_poll.images.contains(img));
                assert!(fetch_image(&client, img).await.is_ok());
            }

            assert!(remove_poll(&user_a, &poll.id).await.is_ok());
            assert!(
                fetch_poll(&client, &poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            let client_images = images.into_iter().skip(6).collect::<Vec<_>>();

            let poll = add_poll(
                &client,
                AddPoll {
                    title: "initially private poll".to_string(),
                    info: "needs to be added to group later".to_string(),
                    ends: f64::MAX,
                    images: client_images.iter().cloned().collect(),
                    voting_limit: 2,
                    group: None,
                },
            )
            .await
            .unwrap();

            assert!(fetch_poll(&client, &poll.id).await.is_ok());
            assert!(
                fetch_poll(&user_a, &poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            // wrong user
            assert!(
                add_poll_to_group(
                    &user_a,
                    &poll.id,
                    &group_id,
                    UpdatedPoll {
                        updated_at: poll.updated_at,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            // wrong poll id
            assert!(
                add_poll_to_group(
                    &client,
                    &poll.id,
                    "abc",
                    UpdatedPoll {
                        updated_at: poll.updated_at,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            // wrong updated_at timestamp
            assert!(
                add_poll_to_group(
                    &client,
                    &poll.id,
                    &group_id,
                    UpdatedPoll { updated_at: 0.0 }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::CONFLICT))
            );

            assert!(
                add_poll_to_group(
                    &client,
                    &poll.id,
                    &group_id,
                    UpdatedPoll {
                        updated_at: poll.updated_at,
                    }
                )
                .await
                .is_ok()
            );

            // already in group
            assert!(
                add_poll_to_group(
                    &client,
                    &poll.id,
                    &group_id,
                    UpdatedPoll {
                        updated_at: poll.updated_at,
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            assert!(fetch_poll(&user_a, &poll.id).await.is_ok());

            assert!(remove_group(&client, &group_id).await.is_ok());

            Ok(())
        });

        sim.run()
    })
}
