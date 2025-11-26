use flare::{
    api::api_params::{
        AddScheduledPoll, ApproveScheduledPollSubmission, EditScheduledPoll,
        EditScheduledPollSubmission, Task,
    },
    time::{now, sim_time::SimClock},
};
use flare_sim::{
    helpers::{
        add_image, add_scheduled_poll, approve_scheduled_poll_submission, edit_scheduled_poll,
        edit_scheduled_poll_submission, fetch_image, fetch_poll, fetch_scheduled_poll,
        fetch_scheduled_poll_submission, fetch_scheduled_poll_submissions, fetch_scheduled_polls,
        fetch_voting_poll, get_client, png_images, remove_scheduled_poll, run_task,
        upload_all_pngs,
    },
    sim::DELAY,
    test_builder::flare_test,
    turmoil,
};
use reqwest::StatusCode;
use sea_entity::api_params::RecurrenceRule;
use tokio::time::sleep;

#[test]
fn test_scheduled_poll_submission() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;
            let other_client = get_client(1).await.0;

            let images = upload_all_pngs(&other_client).await;

            let first_occurrence = now().as_secs_f64() + 10000.0;

            let scheduled_poll = add_scheduled_poll(
                &client,
                AddScheduledPoll {
                    id: None,
                    name: "My scheduled poll".to_string(),
                    first_occurrence,
                    cutoff: 0.0,
                    recurrence_rule: None,
                    submission_limit: None,
                    needs_approval: false,
                    reject_duplicates: false,
                    title_template: "Test".to_string(),
                    info: "some info".to_string(),
                    voting_limit: 3,
                    voting_duration: 60.0,
                    group: None,
                },
            )
            .await
            .unwrap();

            assert!(
                fetch_scheduled_poll_submission(&other_client, &scheduled_poll.id)
                    .await
                    .unwrap()
                    .images
                    .is_empty()
            );

            for images in images.chunks(3) {
                edit_scheduled_poll_submission(
                    &other_client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: images.iter().cloned().collect(),
                        remove_images: vec![],
                    },
                )
                .await
                .unwrap();
            }

            let submission = fetch_scheduled_poll_submission(&other_client, &scheduled_poll.id)
                .await
                .unwrap();

            for image in images {
                assert!(submission.images.contains(&image));
            }

            let images = upload_all_pngs(&other_client).await;

            let scheduled_poll = add_scheduled_poll(
                &client,
                AddScheduledPoll {
                    id: None,
                    name: "My next scheduled poll".to_string(),
                    first_occurrence,
                    cutoff: 0.0,
                    recurrence_rule: None,
                    submission_limit: Some(3),
                    needs_approval: false,
                    reject_duplicates: false,
                    title_template: "Test 2".to_string(),
                    info: "some more info".to_string(),
                    voting_limit: 3,
                    voting_duration: 60.0,
                    group: None,
                },
            )
            .await
            .unwrap();

            for i in 0..4 {
                if i < 3 {
                    edit_scheduled_poll_submission(
                        &other_client,
                        &scheduled_poll.id,
                        EditScheduledPollSubmission {
                            add_images: vec![images[i].clone()],
                            remove_images: vec![],
                        },
                    )
                    .await
                    .unwrap();
                } else {
                    assert!(
                        edit_scheduled_poll_submission(
                            &other_client,
                            &scheduled_poll.id,
                            EditScheduledPollSubmission {
                                add_images: vec![images[i].clone()],
                                remove_images: vec![],
                            },
                        )
                        .await
                        .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
                    );
                }
            }

            let submission = fetch_scheduled_poll_submission(&other_client, &scheduled_poll.id)
                .await
                .unwrap();

            for image in &images[0..3] {
                assert!(submission.images.contains(image));
                edit_scheduled_poll_submission(
                    &other_client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![],
                        remove_images: vec![image.clone()],
                    },
                )
                .await
                .unwrap();
            }

            assert!(
                edit_scheduled_poll_submission(
                    &other_client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![images[5].clone()],
                        remove_images: vec![],
                    },
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
fn test_scheduled_poll_add_remove() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;
            let other_client = get_client(1).await.0;

            let images = upload_all_pngs(&other_client).await;

            let first_occurrence = now().as_secs_f64() + 60.0 * 30.0;

            let scheduled_poll = add_scheduled_poll(
                &client,
                AddScheduledPoll {
                    id: None,
                    name: "My scheduled poll".to_string(),
                    first_occurrence,
                    cutoff: 0.0,
                    recurrence_rule: Some(RecurrenceRule::Weekly { interval_weeks: 1 }),
                    submission_limit: Some(3),
                    needs_approval: false,
                    reject_duplicates: false,
                    title_template: "Some title".to_string(),
                    info: "Some info".to_string(),
                    voting_limit: 3,
                    voting_duration: 60.0 * 60.0 * 24.0,
                    group: None,
                },
            )
            .await
            .unwrap();

            for image in &images[0..3] {
                edit_scheduled_poll_submission(
                    &other_client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![image.clone()],
                        remove_images: vec![],
                    },
                )
                .await
                .unwrap();
            }

            assert!(
                edit_scheduled_poll_submission(
                    &other_client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![images[3].clone()],
                        remove_images: vec![]
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            run_task(
                &client,
                &Task::RunScheduledPoll(scheduled_poll.id.parse().unwrap()),
            )
            .await
            .unwrap();

            sleep(DELAY).await;

            assert!(
                fetch_scheduled_poll(&client, &scheduled_poll.id)
                    .await
                    .unwrap()
                    .polls
                    .is_empty()
            );

            SimClock::add_offset(60.0 * 60.0 * 24.0 * 8.0);

            run_task(
                &client,
                &flare::api::api_params::Task::RunScheduledPoll(scheduled_poll.id.parse().unwrap()),
            )
            .await
            .unwrap();

            sleep(DELAY).await;

            for image in &images[3..6] {
                edit_scheduled_poll_submission(
                    &other_client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![image.clone()],
                        remove_images: vec![],
                    },
                )
                .await
                .unwrap();
            }

            let scheduled_poll = fetch_scheduled_poll(&client, &scheduled_poll.id)
                .await
                .unwrap();

            assert_eq!(scheduled_poll.polls.len(), 1);

            let created_poll = fetch_poll(&client, &scheduled_poll.polls[0]).await.unwrap();
            for image in &images[0..3] {
                assert!(created_poll.images.contains(image));
            }

            let scheduled_polls = fetch_scheduled_polls(&client, None, None).await.unwrap();

            assert_eq!(scheduled_polls.polls.len(), 1);
            assert_eq!(scheduled_polls.polls[0].id, scheduled_poll.id);

            assert!(
                remove_scheduled_poll(&client, &scheduled_poll.id)
                    .await
                    .is_ok()
            );

            assert_eq!(
                fetch_scheduled_polls(&client, None, None)
                    .await
                    .unwrap()
                    .polls
                    .len(),
                0
            );
            assert!(
                fetch_scheduled_poll(&client, &scheduled_poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            assert!(
                edit_scheduled_poll_submission(
                    &other_client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![],
                        remove_images: vec![]
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            for image in &images[0..6] {
                assert!(
                    fetch_image(&client, image)
                        .await
                        .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
                );
                assert!(
                    fetch_image(&other_client, image)
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
fn test_scheduled_poll_edit() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;

            let images = upload_all_pngs(&client).await;
            let first_occurrence = now().as_secs_f64() + 60.0 * 30.0;

            let scheduled_poll = add_scheduled_poll(
                &client,
                AddScheduledPoll {
                    id: None,
                    name: "My scheduled poll".to_string(),
                    first_occurrence,
                    cutoff: 0.0,
                    recurrence_rule: Some(RecurrenceRule::Weekly { interval_weeks: 1 }),
                    submission_limit: Some(3),
                    needs_approval: false,
                    reject_duplicates: false,
                    title_template: "Some title".to_string(),
                    info: "info".to_string(),
                    voting_limit: 3,
                    voting_duration: 60.0 * 60.0 * 24.0,
                    group: None,
                },
            )
            .await
            .unwrap();

            for image in &images[0..3] {
                edit_scheduled_poll_submission(
                    &client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![image.clone()],
                        remove_images: vec![],
                    },
                )
                .await
                .unwrap();
            }

            assert!(
                edit_scheduled_poll_submission(
                    &client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![images[3].clone()],
                        remove_images: vec![],
                    },
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            SimClock::add_offset(60.0 * 60.0 * 24.0 * 8.0);

            run_task(
                &client,
                &Task::RunScheduledPoll(scheduled_poll.id.parse().unwrap()),
            )
            .await
            .unwrap();

            sleep(DELAY).await;

            let scheduled_poll = fetch_scheduled_poll(&client, &scheduled_poll.id)
                .await
                .unwrap();

            assert_eq!(scheduled_poll.name, "My scheduled poll");
            assert_eq!(scheduled_poll.polls.len(), 1);
            assert_eq!(
                fetch_poll(&client, &scheduled_poll.polls[0])
                    .await
                    .unwrap()
                    .title,
                "Some title"
            );
            assert_eq!(
                fetch_voting_poll(&client, &scheduled_poll.polls[0])
                    .await
                    .unwrap()
                    .voting_limit,
                3
            );

            edit_scheduled_poll(
                &client,
                &scheduled_poll.id,
                EditScheduledPoll {
                    name: Some("some other name".to_string()),
                    next_occurrence: None,
                    cutoff: None,
                    recurrence_rule: None,
                    submission_limit: Some(Some(4)),
                    needs_approval: None,
                    reject_duplicates: None,
                    title_template: Some("different title".to_string()),
                    info: None,
                    voting_limit: Some(2),
                    voting_duration: None,
                    updated_at: scheduled_poll.updated_at,
                },
            )
            .await
            .unwrap();

            for image in &images[3..7] {
                edit_scheduled_poll_submission(
                    &client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![image.clone()],
                        remove_images: vec![],
                    },
                )
                .await
                .unwrap();
            }

            assert!(
                edit_scheduled_poll_submission(
                    &client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![images[7].clone()],
                        remove_images: vec![],
                    },
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::BAD_REQUEST))
            );

            SimClock::add_offset(60.0 * 60.0 * 24.0 * 8.0);

            run_task(
                &client,
                &Task::RunScheduledPoll(scheduled_poll.id.parse().unwrap()),
            )
            .await
            .unwrap();

            sleep(DELAY).await;

            let scheduled_poll = fetch_scheduled_poll(&client, &scheduled_poll.id)
                .await
                .unwrap();

            assert_eq!(scheduled_poll.name, "some other name");
            assert_eq!(scheduled_poll.polls.len(), 2);

            // old poll stays the same
            assert_eq!(
                fetch_poll(&client, &scheduled_poll.polls[1])
                    .await
                    .unwrap()
                    .title,
                "Some title"
            );
            assert_eq!(
                fetch_voting_poll(&client, &scheduled_poll.polls[1])
                    .await
                    .unwrap()
                    .voting_limit,
                3
            );

            // new poll applies new options
            assert_eq!(
                fetch_poll(&client, &scheduled_poll.polls[0])
                    .await
                    .unwrap()
                    .title,
                "different title"
            );
            assert_eq!(
                fetch_voting_poll(&client, &scheduled_poll.polls[0])
                    .await
                    .unwrap()
                    .voting_limit,
                2
            );

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_scheduled_poll_approval() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;
            let other_client = get_client(1).await.0;

            let images = upload_all_pngs(&other_client).await;

            let first_occurrence = now().as_secs_f64() + 60.0 * 30.0;

            let scheduled_poll = add_scheduled_poll(
                &client,
                AddScheduledPoll {
                    id: None,
                    name: "Scheduled poll".to_string(),
                    first_occurrence,
                    cutoff: 0.0,
                    recurrence_rule: Some(RecurrenceRule::Weekly { interval_weeks: 1 }),
                    submission_limit: None,
                    needs_approval: true,
                    reject_duplicates: false,
                    title_template: "Foo".to_string(),
                    info: "".to_string(),
                    voting_limit: 3,
                    voting_duration: 60.0 * 60.0 * 24.0,
                    group: None,
                },
            )
            .await
            .unwrap();

            for image in &images[0..3] {
                edit_scheduled_poll_submission(
                    &other_client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![image.clone()],
                        remove_images: vec![],
                    },
                )
                .await
                .unwrap();
            }

            SimClock::add_offset(60.0 * 60.0 * 24.0 * 8.0);

            run_task(
                &client,
                &Task::RunScheduledPoll(scheduled_poll.id.parse().unwrap()),
            )
            .await
            .unwrap();

            sleep(DELAY).await;

            // the poll should have been created, but no images have been approved yet, so the task will terminate

            assert!(
                fetch_scheduled_poll(&client, &scheduled_poll.id)
                    .await
                    .unwrap()
                    .polls
                    .is_empty()
            );

            assert!(
                fetch_scheduled_poll_submissions(&other_client, &scheduled_poll.id)
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
            );

            let submissions = fetch_scheduled_poll_submissions(&client, &scheduled_poll.id)
                .await
                .unwrap();

            assert_eq!(submissions.submissions.len(), 3);

            for submission in submissions.submissions {
                let approve = ApproveScheduledPollSubmission {
                    image_id: submission.image_id,
                    approved: true,
                };
                assert!(
                    approve_scheduled_poll_submission(
                        &other_client,
                        &scheduled_poll.id,
                        approve.clone()
                    )
                    .await
                    .is_err_and(|e| e.status() == Some(StatusCode::NOT_FOUND))
                );

                approve_scheduled_poll_submission(&client, &scheduled_poll.id, approve.clone())
                    .await
                    .unwrap();
            }

            let submissions = fetch_scheduled_poll_submissions(&client, &scheduled_poll.id)
                .await
                .unwrap();

            assert!(submissions.submissions.iter().all(|e| e.approved));

            run_task(
                &client,
                &Task::RunScheduledPoll(scheduled_poll.id.parse().unwrap()),
            )
            .await
            .unwrap();

            sleep(DELAY).await;

            let poll = fetch_poll(
                &client,
                fetch_scheduled_poll(&client, &scheduled_poll.id)
                    .await
                    .unwrap()
                    .polls
                    .first()
                    .unwrap(),
            )
            .await
            .unwrap();

            assert_eq!(poll.images.len(), 3);

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_scheduled_poll_duplicates() -> turmoil::Result {
    flare_test(|sim| {
        sim.create_basic_scenario();

        sim.client("client", async move {
            let client = get_client(0).await.0;
            let other_client = get_client(1).await.0;

            let first_occurrence = now().as_secs_f64() + 60.0 * 30.0;

            let scheduled_poll = add_scheduled_poll(
                &client,
                AddScheduledPoll {
                    id: None,
                    name: "Scheduled poll".to_string(),
                    first_occurrence,
                    cutoff: 0.0,
                    recurrence_rule: Some(RecurrenceRule::Weekly { interval_weeks: 1 }),
                    submission_limit: None,
                    needs_approval: true,
                    reject_duplicates: true,
                    title_template: "Foo".to_string(),
                    info: "".to_string(),
                    voting_limit: 3,
                    voting_duration: 60.0 * 60.0 * 24.0,
                    group: None,
                },
            )
            .await
            .unwrap();

            let img = png_images()[0];

            let image_1 = add_image(&other_client, img, "image/png")
                .await
                .unwrap()
                .name;
            let image_2 = add_image(&other_client, img, "image/png")
                .await
                .unwrap()
                .name;

            assert!(
                edit_scheduled_poll_submission(
                    &other_client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![image_1],
                        remove_images: vec![]
                    }
                )
                .await
                .is_ok()
            );

            assert!(
                edit_scheduled_poll_submission(
                    &other_client,
                    &scheduled_poll.id,
                    EditScheduledPollSubmission {
                        add_images: vec![image_2],
                        remove_images: vec![]
                    }
                )
                .await
                .is_err_and(|e| e.status() == Some(StatusCode::CONFLICT))
            );

            Ok(())
        });

        sim.run()
    })
}
