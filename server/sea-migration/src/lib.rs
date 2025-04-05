pub use sea_orm_migration::prelude::*;

mod m20241121_205854_init_database;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20241121_205854_init_database::Migration)]
    }
}
