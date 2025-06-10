use extension::postgres::Type;
use sea_orm_migration::{
    prelude::*,
    schema::*,
    sea_orm::{DbBackend, Statement},
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // TODO each of these needs an index (or multiple)
        // e.g. .index(Index::create().unique().name("idx-user-id").col(User::Id)) //though no need for indexes on unique / primary cols obviously

        let current_ts = Expr::cust(r"EXTRACT(epoch FROM now())");

        manager
            .create_type(
                Type::create()
                    .as_enum(Permissions::Enum)
                    .values([
                        Permissions::Admin,
                        Permissions::ManageGroups,
                        Permissions::ManagePolls,
                    ])
                    .to_owned(),
            )
            .await?;

        manager
            .create_type(
                Type::create()
                    .as_enum(OAuthProvider::Enum)
                    .values([OAuthProvider::Discord, OAuthProvider::Github])
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .if_not_exists()
                    .col(string(User::Id).primary_key())
                    .col(array(
                        User::Permissions,
                        ColumnType::Enum {
                            name: Permissions::Enum.into_iden(),
                            variants: Permissions::Enum
                                .into_iter()
                                .map(IntoIden::into_iden)
                                .collect(),
                        },
                    ))
                    .col(double(User::CreatedAt).default(current_ts.clone()))
                    .col(double(User::UpdatedAt).default(current_ts.clone()))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(OAuthUser::Table)
                    .if_not_exists()
                    .primary_key(
                        Index::create()
                            .col(OAuthUser::UserId)
                            .col(OAuthUser::Provider),
                    )
                    .col(string(OAuthUser::UserId).not_null())
                    .col(string(OAuthUser::ProviderUserId).not_null())
                    .col(
                        ColumnDef::new(OAuthUser::Provider)
                            .custom(OAuthProvider::Enum)
                            .not_null(),
                    )
                    .col(double(OAuthUser::CreatedAt).default(current_ts.clone()))
                    .foreign_key(
                        ForeignKey::create()
                            .from(OAuthUser::Table, OAuthUser::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Group::Table)
                    .if_not_exists()
                    .col(string(Group::Id).primary_key())
                    .col(string(Group::OwnerId))
                    .col(string(Group::Name).not_null())
                    .col(double(Group::CreatedAt).default(current_ts.clone()))
                    .col(double(Group::UpdatedAt).default(current_ts.clone()))
                    .foreign_key(
                        ForeignKey::create()
                            .from(Group::Table, Group::OwnerId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(GroupUser::Table)
                    .if_not_exists()
                    .primary_key(
                        Index::create()
                            .col(GroupUser::GroupId)
                            .col(GroupUser::UserId),
                    )
                    .col(string(GroupUser::GroupId).not_null())
                    .col(string(GroupUser::UserId).not_null())
                    .col(double(GroupUser::CreatedAt).default(current_ts.clone()))
                    .foreign_key(
                        ForeignKey::create()
                            .from(GroupUser::Table, GroupUser::GroupId)
                            .to(Group::Table, Group::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(GroupUser::Table, GroupUser::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(GroupJoinRequest::Table)
                    .if_not_exists()
                    .primary_key(
                        Index::create()
                            .col(GroupJoinRequest::GroupId)
                            .col(GroupJoinRequest::UserId),
                    )
                    .col(string(GroupJoinRequest::GroupId).not_null())
                    .col(string(GroupJoinRequest::UserId).not_null())
                    .col(double(GroupJoinRequest::CreatedAt).default(current_ts.clone()))
                    .foreign_key(
                        ForeignKey::create()
                            .from(GroupJoinRequest::Table, GroupJoinRequest::GroupId)
                            .to(Group::Table, Group::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(GroupJoinRequest::Table, GroupJoinRequest::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Poll::Table)
                    .if_not_exists()
                    .col(string(Poll::Id).primary_key())
                    .col(string(Poll::Title)) // TODO string_len?
                    .col(string(Poll::Info))
                    .col(double(Poll::Ends))
                    .col(boolean(Poll::Locked).default(false))
                    .col(boolean(Poll::ResultsPublic).default(false))
                    .col(integer(Poll::AllowedVotes))
                    .col(string_null(Poll::GroupId))
                    .col(string_null(Poll::OwnerId))
                    .col(double(Poll::CreatedAt).default(current_ts.clone()))
                    .col(double(Poll::UpdatedAt).default(current_ts.clone()))
                    .foreign_key(
                        ForeignKey::create()
                            .from(Poll::Table, Poll::GroupId)
                            .to(Group::Table, Group::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Poll::Table, Poll::OwnerId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-poll-created-at")
                    .table(Poll::Table)
                    .col(Poll::CreatedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-poll-ends")
                    .table(Poll::Table)
                    .col(Poll::Ends)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Image::Table)
                    .if_not_exists()
                    .col(string(Image::Id).primary_key())
                    .col(string(Image::Mime))
                    .col(string(Image::AspectRatio))
                    .col(string_len(Image::Hash, 128))
                    .col(string_null(Poll::GroupId))
                    .col(string_null(Poll::OwnerId))
                    .col(string_null(Image::PollId))
                    .col(double(Image::CreatedAt).default(current_ts.clone()))
                    .foreign_key(
                        ForeignKey::create()
                            .from(Image::Table, Image::GroupId)
                            .to(Group::Table, Group::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Image::Table, Image::OwnerId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Image::Table, Image::PollId)
                            .to(Poll::Table, Poll::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Vote::Table)
                    .if_not_exists()
                    .col(integer(Vote::Id).primary_key().auto_increment())
                    .col(string(Vote::ImageId))
                    .col(double(Vote::CreatedAt).default(current_ts.clone()))
                    .foreign_key(
                        ForeignKey::create()
                            .from(Vote::Table, Vote::ImageId)
                            .to(Image::Table, Image::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(EphemeralUser::Table)
                    .if_not_exists()
                    .col(integer(EphemeralUser::Id).primary_key().auto_increment())
                    .col(string_len(EphemeralUser::Cookie, 24))
                    .col(string_len(EphemeralUser::Ip, 128))
                    .col(double(EphemeralUser::CreatedAt).default(current_ts.clone()))
                    .col(double(EphemeralUser::LastSeenAt).default(current_ts.clone()))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(EphemeralUserVote::Table)
                    .if_not_exists()
                    .primary_key(
                        Index::create()
                            .col(EphemeralUserVote::VoteId)
                            .col(EphemeralUserVote::EphemeralUserId),
                    )
                    .col(integer(EphemeralUserVote::VoteId).not_null())
                    .col(integer(EphemeralUserVote::EphemeralUserId).not_null())
                    .col(double(EphemeralUserVote::CreatedAt).default(current_ts.clone()))
                    .foreign_key(
                        ForeignKey::create()
                            .from(EphemeralUserVote::Table, EphemeralUserVote::VoteId)
                            .to(Vote::Table, Vote::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(EphemeralUserVote::Table, EphemeralUserVote::EphemeralUserId)
                            .to(EphemeralUser::Table, EphemeralUser::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        db.execute(Statement::from_string(
            DbBackend::Postgres,
            "
                CREATE OR REPLACE FUNCTION set_updated_at()
                RETURNS TRIGGER AS $$
                BEGIN
                    NEW.updated_at = EXTRACT(epoch FROM now());
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
                ",
        ))
        .await?;

        for table in [
            User::Table.to_string(),
            Group::Table.to_string(),
            Poll::Table.to_string(),
        ] {
            db.execute(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    r#"
                    CREATE OR REPLACE TRIGGER updated_at
                    BEFORE UPDATE ON "{}"
                    FOR EACH ROW
                    EXECUTE FUNCTION set_updated_at();
                    "#,
                    table
                ),
            ))
            .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        for table in [
            User::Table.to_string(),
            Group::Table.to_string(),
            Poll::Table.to_string(),
        ] {
            db.execute(Statement::from_string(
                DbBackend::Postgres,
                format!(r#"DROP TRIGGER IF EXISTS updated_at ON "{}";"#, table),
            ))
            .await?;
        }

        manager
            .drop_table(
                Table::drop()
                    .if_exists()
                    .table(EphemeralUserVote::Table)
                    .table(EphemeralUser::Table)
                    .table(Vote::Table)
                    .table(Image::Table)
                    .table(Poll::Table)
                    .table(GroupJoinRequest::Table)
                    .table(GroupUser::Table)
                    .table(Group::Table)
                    .table(OAuthUser::Table)
                    .table(User::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_type(
                Type::drop()
                    .if_exists()
                    .names([
                        SeaRc::new(Permissions::Enum) as DynIden,
                        SeaRc::new(OAuthProvider::Enum) as DynIden,
                    ])
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Permissions {
    #[sea_orm(iden = "permissions")]
    Enum,
    Admin,
    ManageGroups,
    ManagePolls,
}

#[derive(DeriveIden)]
enum OAuthProvider {
    #[sea_orm(iden = "oauth_provider")]
    Enum,
    Discord,
    Github,
}

#[derive(DeriveIden)]
enum User {
    Table,
    Id,
    Permissions,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum OAuthUser {
    Table,
    UserId,
    ProviderUserId,
    Provider,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Group {
    Table,
    Id,
    OwnerId,
    Name,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum GroupUser {
    Table,
    GroupId,
    UserId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum GroupJoinRequest {
    Table,
    GroupId,
    UserId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Poll {
    Table,
    Id,
    Title,
    Info,
    Ends,
    Locked,
    ResultsPublic,
    AllowedVotes,
    GroupId,
    OwnerId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Image {
    Table,
    Id,
    Mime,
    AspectRatio,
    Hash,
    GroupId,
    OwnerId,
    PollId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Vote {
    Table,
    Id,
    ImageId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum EphemeralUser {
    Table,
    Id,
    Cookie,
    Ip,
    CreatedAt,
    LastSeenAt,
}

#[derive(DeriveIden)]
enum EphemeralUserVote {
    Table,
    VoteId,
    EphemeralUserId,
    CreatedAt,
}
