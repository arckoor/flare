use flare::{
    api::api_params::Vote,
    tasks::Tasks,
    time::{ONE_MINUTE, ONE_WEEK, now},
};
use flare_sim::{
    helpers::{get_client, png_images, vote},
    sim::{TempDir, setup_db},
    test_builder::flare_test,
    turmoil,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait,
    QueryFilter, prelude::Expr,
};

#[test]
fn test_clean_old_invites() -> turmoil::Result {
    flare_test(|sim| {
        sim.client("client", async move {
            let db = setup_db().await;

            let user = sea_entity::user::ActiveModel {
                id: Set("abc".to_string()),
                permissions: Set(vec![]),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            let group = sea_entity::group::ActiveModel {
                id: Set("def".to_string()),
                name: Set("test-group".to_string()),
                owner_id: Set(user.id.clone()),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            sea_entity::group_join_request::ActiveModel {
                group_id: Set(group.id.clone()),
                user_id: Set(user.id.clone()),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            Tasks::clean_old_invites(db.clone()).await;

            let mut invite = sea_entity::group_join_request::Entity::find_by_id((
                group.id.clone(),
                user.id.clone(),
            ))
            .one(&db.sea)
            .await
            .unwrap()
            .unwrap()
            .into_active_model();

            invite.created_at = Set(now().as_secs_f64() - (ONE_WEEK * 2.0));
            invite.save(&db.sea).await.unwrap();

            Tasks::clean_old_invites(db.clone()).await;

            assert!(
                sea_entity::group_join_request::Entity::find_by_id((
                    group.id.clone(),
                    user.id.clone()
                ))
                .one(&db.sea)
                .await
                .unwrap()
                .is_none()
            );
            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_clean_old_images() -> turmoil::Result {
    flare_test(|sim| {
        sim.client("client", async move {
            let db = setup_db().await;
            let temp_dir = TempDir::new().unwrap();
            let image_path = temp_dir.path().to_path_buf();
            let image = temp_dir.path().join("123.png");

            tokio::fs::write(&image, png_images()[0]).await.unwrap();

            Tasks::clean_old_images(db.clone(), image_path.clone()).await;
            assert!(!image.exists());

            tokio::fs::write(&image, png_images()[0]).await.unwrap();
            let user = sea_entity::user::ActiveModel {
                id: Set("abc".to_string()),
                permissions: Set(vec![]),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            let db_image = sea_entity::image::ActiveModel {
                id: Set("123.png".to_string()),
                aspect_ratio: Set("1/1".to_string()),
                mime: Set("image/png".to_string()),
                hash: Set("".to_string()),
                owner_id: Set(Some(user.id.clone())),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            assert!(image.exists());
            Tasks::clean_old_images(db.clone(), image_path.clone()).await;
            assert!(image.exists());

            let mut db_image = db_image.into_active_model();
            db_image.created_at = Set(now().as_secs_f64() - (ONE_WEEK * 2.0));
            db_image.save(&db.sea).await.unwrap();

            Tasks::clean_old_images(db.clone(), image_path.clone()).await;
            assert!(!image.exists());

            let poll = sea_entity::poll::ActiveModel {
                id: Set("def".to_string()),
                title: Set("test poll".to_string()),
                info: Set("test poll".to_string()),
                ends: Set(f64::MAX),
                results_public: Set(false),
                voting_limit: Set(2),
                owner_id: Set(Some(user.id.clone())),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            tokio::fs::write(&image, png_images()[0]).await.unwrap();
            let db_image = sea_entity::image::ActiveModel {
                id: Set("123.png".to_string()),
                aspect_ratio: Set("1/1".to_string()),
                mime: Set("image/png".to_string()),
                hash: Set("".to_string()),
                owner_id: Set(Some(user.id.clone())),
                poll_id: Set(Some(poll.id.clone())),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            assert!(image.exists());
            Tasks::clean_old_images(db.clone(), image_path.clone()).await;
            assert!(image.exists());

            let mut db_image = db_image.into_active_model();
            db_image.created_at = Set(now().as_secs_f64() - (ONE_WEEK * 2.0));
            db_image.save(&db.sea).await.unwrap();

            Tasks::clean_old_images(db.clone(), image_path.clone()).await;
            assert!(image.exists());

            sea_entity::image::Entity::delete_by_id("123.png")
                .exec(&db.sea)
                .await
                .unwrap();
            poll.into_active_model().delete(&db.sea).await.unwrap();
            Tasks::clean_old_images(db.clone(), image_path.clone()).await;
            assert!(!image.exists());

            tokio::fs::write(&image, png_images()[0]).await.unwrap();
            let db_image = sea_entity::image::ActiveModel {
                id: Set("123.png".to_string()),
                aspect_ratio: Set("1/1".to_string()),
                mime: Set("image/png".to_string()),
                hash: Set("".to_string()),
                owner_id: Set(Some(user.id.clone())),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            sea_entity::scheduled_poll::ActiveModel {
                id: Set("hij".to_string()),
                name: Set("hij".to_string()),
                next_occurrence: Set(0.0),
                cutoff: Set(0.0),
                voting_duration: Set(0.0),
                submission_limit: Set(None),
                title_template: Set("title".to_string()),
                info: Set("info".to_string()),
                voting_limit: Set(3),
                needs_approval: Set(false),
                reject_duplicates: Set(false),
                owner_id: Set(Some(user.id.clone())),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            let scheduled_image = sea_entity::scheduled_image::ActiveModel {
                next_occurrence: Set(0.0),
                scheduled_poll_id: Set("hij".to_string()),
                image_id: Set("123.png".to_string()),
                approved: Set(false),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            Tasks::clean_old_images(db.clone(), image_path.clone()).await;
            assert!(image.exists());

            let mut db_image = db_image.into_active_model();
            db_image.created_at = Set(now().as_secs_f64() - (ONE_WEEK * 2.0));
            db_image.save(&db.sea).await.unwrap();

            Tasks::clean_old_images(db.clone(), image_path.clone()).await;
            assert!(image.exists());

            scheduled_image
                .into_active_model()
                .delete(&db.sea)
                .await
                .unwrap();

            Tasks::clean_old_images(db.clone(), image_path.clone()).await;
            assert!(!image.exists());

            Ok(())
        });

        sim.run()
    })
}

#[test]
fn test_lock_old_polls_and_expire_old_users() -> turmoil::Result {
    flare_test(|sim| {
        sim.start_api();

        sim.client("client", async move {
            let db = setup_db().await;

            let user = sea_entity::user::ActiveModel {
                id: Set("abc".to_string()),
                permissions: Set(vec![]),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            let poll_1 = sea_entity::poll::ActiveModel {
                id: Set("poll1".to_string()),
                title: Set("".to_string()),
                info: Set("".to_string()),
                ends: Set(f64::MAX),
                results_public: Set(false),
                voting_limit: Set(2),
                group_id: Set(None),
                owner_id: Set(Some(user.id.clone())),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            let poll_2 = sea_entity::poll::ActiveModel {
                id: Set("poll2".to_string()),
                title: Set("".to_string()),
                info: Set("".to_string()),
                ends: Set(f64::MAX),
                results_public: Set(false),
                voting_limit: Set(2),
                owner_id: Set(Some(user.id.clone())),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            // images for poll 1
            for image in ["1.png", "2.png", "3.png"] {
                sea_entity::image::ActiveModel {
                    id: Set(image.to_string()),
                    aspect_ratio: Set("1/1".to_string()),
                    mime: Set("image/png".to_string()),
                    hash: Set("".to_string()),
                    owner_id: Set(Some(user.id.clone())),
                    poll_id: Set(Some(poll_1.id.clone())),
                    ..Default::default()
                }
                .insert(&db.sea)
                .await
                .unwrap();
            }

            // image for poll 2
            sea_entity::image::ActiveModel {
                id: Set("4.png".to_string()),
                aspect_ratio: Set("1/1".to_string()),
                mime: Set("image/png".to_string()),
                hash: Set("".to_string()),
                owner_id: Set(Some(user.id.clone())),
                poll_id: Set(Some(poll_2.id.clone())),
                ..Default::default()
            }
            .insert(&db.sea)
            .await
            .unwrap();

            // 1 votes for one poll, 2 for two
            let user_1 = get_client(1).await.0;
            let user_2 = get_client(2).await.0;

            vote(
                &user_1,
                &poll_1.id,
                Vote {
                    votes: ["1.png".to_string(), "2.png".to_string()].into(),
                },
            )
            .await
            .unwrap();

            vote(
                &user_2,
                &poll_1.id,
                Vote {
                    votes: ["2.png".to_string(), "3.png".to_string()].into(),
                },
            )
            .await
            .unwrap();

            vote(
                &user_2,
                &poll_2.id,
                Vote {
                    votes: ["4.png".to_string()].into(),
                },
            )
            .await
            .unwrap();

            assert_eq!(
                sea_entity::poll::Entity::find()
                    .filter(sea_entity::poll::Column::Locked.eq(false))
                    .all(&db.sea)
                    .await
                    .unwrap()
                    .len(),
                2
            );

            Tasks::lock_old_polls(db.clone()).await;

            // nothing should change
            assert_eq!(
                sea_entity::poll::Entity::find()
                    .filter(sea_entity::poll::Column::Locked.eq(false))
                    .count(&db.sea)
                    .await
                    .unwrap(),
                2
            );

            assert_eq!(
                sea_entity::ephemeral_user_vote::Entity::find()
                    .count(&db.sea)
                    .await
                    .unwrap(),
                5
            );

            assert_eq!(
                sea_entity::vote::Entity::find()
                    .count(&db.sea)
                    .await
                    .unwrap(),
                5
            );

            assert_eq!(
                sea_entity::ephemeral_user::Entity::find()
                    .count(&db.sea)
                    .await
                    .unwrap(),
                2
            );

            let mut poll_1 = poll_1.into_active_model();
            poll_1.ends = Set(now().as_secs_f64() - (ONE_WEEK * 2.0 + ONE_MINUTE));
            poll_1.save(&db.sea).await.unwrap();

            Tasks::lock_old_polls(db.clone()).await;

            assert!(
                sea_entity::poll::Entity::find_by_id("poll1")
                    .one(&db.sea)
                    .await
                    .unwrap()
                    .unwrap()
                    .locked
            );

            // the four votes for poll 1 disappear

            assert_eq!(
                sea_entity::ephemeral_user_vote::Entity::find()
                    .count(&db.sea)
                    .await
                    .unwrap(),
                1
            );

            assert_eq!(
                sea_entity::poll::Entity::find()
                    .filter(sea_entity::poll::Column::Locked.eq(false))
                    .all(&db.sea)
                    .await
                    .unwrap()
                    .len(),
                1
            );

            assert_eq!(
                sea_entity::vote::Entity::find()
                    .count(&db.sea)
                    .await
                    .unwrap(),
                5
            );

            // users stay intact

            assert_eq!(
                sea_entity::ephemeral_user::Entity::find()
                    .count(&db.sea)
                    .await
                    .unwrap(),
                2
            );

            sea_entity::ephemeral_user::Entity::update_many()
                .col_expr(
                    sea_entity::ephemeral_user::Column::LastSeenAt,
                    Expr::value(0.0),
                )
                .exec(&db.sea)
                .await
                .unwrap();

            Tasks::expire_old_ephemeral_users(db.clone()).await;

            // one ephemeral user disappears

            assert_eq!(
                sea_entity::ephemeral_user::Entity::find()
                    .count(&db.sea)
                    .await
                    .unwrap(),
                1
            );

            let mut poll_2 = poll_2.into_active_model();
            poll_2.ends = Set(now().as_secs_f64() - (ONE_WEEK * 2.0 + ONE_MINUTE));
            poll_2.save(&db.sea).await.unwrap();

            Tasks::lock_old_polls(db.clone()).await;

            // other user still present

            assert_eq!(
                sea_entity::poll::Entity::find()
                    .filter(sea_entity::poll::Column::Locked.eq(false))
                    .all(&db.sea)
                    .await
                    .unwrap()
                    .len(),
                0
            );

            assert_eq!(
                sea_entity::ephemeral_user::Entity::find()
                    .count(&db.sea)
                    .await
                    .unwrap(),
                1
            );

            Tasks::expire_old_ephemeral_users(db.clone()).await;

            // now it disappears too

            assert_eq!(
                sea_entity::ephemeral_user::Entity::find()
                    .count(&db.sea)
                    .await
                    .unwrap(),
                0
            );

            Ok(())
        });

        sim.run()
    })
}
