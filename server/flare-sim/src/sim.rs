use std::future::Future;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use flare::api::api_params::AddGroup;
use flare::db::Database;
pub use tempfile::TempDir;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::prelude::*;
use turmoil::{Result, Sim, ToIpAddr};

use crate::helpers::{self};
use flare;
use flare::config::FlareConfig;

pub const FLARE_SERVER: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
pub const FLARE_PORT: u16 = 9000;
pub const PG_URL: &'static str = concat!(env!("PG_BASE"), "/flare-db-test");
pub const DELAY: Duration = Duration::from_secs(20);

pub struct FlareSimulation<'a> {
    pub working_dir: TempDir,
    pub sim: Sim<'a>,

    #[allow(unused)]
    tracing_subscriber_guard: DefaultGuard,
}

impl<'a> FlareSimulation<'a> {
    pub fn new(sim: Sim<'a>) -> Self {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            );

        let guard = tracing::subscriber::set_default(subscriber);

        let working_dir = TempDir::new().expect("Failed to create temp dir");
        Self {
            working_dir,
            sim,
            tracing_subscriber_guard: guard,
        }
    }

    pub fn client<F>(&mut self, addr: impl ToIpAddr, client: F)
    where
        F: Future<Output = Result> + 'static,
    {
        self.sim.client(addr, client);
    }

    pub fn host<F, Fut>(&mut self, addr: impl ToIpAddr, host: F)
    where
        F: Fn() -> Fut + 'a,
        Fut: Future<Output = Result> + 'static,
    {
        self.sim.host(addr, host);
    }

    pub fn start_api(&mut self) {
        let addr = FLARE_SERVER;
        let path = self.working_dir.path().join(addr.to_string());
        std::fs::create_dir(&path).expect("Failed to create dir");

        self.host(FLARE_SERVER, move || {
            let mut config = FlareConfig::default();
            config.store.storage.base_path = path.clone();
            config.store.storage.postgres_url = PG_URL.to_string();
            config.store.storage.admin.github_id = None;
            config.store.storage.admin.discord_id = Some("admin".to_string());
            config.server.port = FLARE_PORT;

            async move { flare::launch(config).await.map_err(|e| e.into()) }
        });

        self.client("startup-client", async move {
            let client = helpers::Http::new_with_cookies(true, "startup-client".to_string());
            helpers::wait_for_api(&client).await;

            Ok(())
        });

        self.run().unwrap();
    }

    pub fn create_basic_scenario(&mut self) {
        self.start_api();

        self.client("login-client", async move {
            let mut client = helpers::Http::new_with_cookies(true, "login-client".to_string());
            for login_info in helpers::logins() {
                helpers::login(&mut client, &login_info).await.unwrap();
                helpers::logout(&mut client).await.unwrap();
            }

            Ok(())
        });

        self.run().unwrap();
    }

    pub fn group_users(&mut self, group_name: &str, owner: usize, users: Vec<usize>) {
        let group_name = group_name.to_string();
        self.client(format!("group-users-client-{}", group_name), async move {
            let mut owner_client = helpers::get_client(owner).await.0;

            let group = helpers::add_group(&owner_client, AddGroup { name: group_name })
                .await
                .unwrap();

            helpers::refresh(&mut owner_client).await.unwrap();

            for user in users {
                let (user_client, user_id) = helpers::get_client(user).await;

                helpers::add_group_user(&owner_client, &group.id, &user_id)
                    .await
                    .unwrap();

                helpers::join_group(&user_client, &group.id).await.unwrap();
            }

            Ok(())
        });

        self.run().unwrap();
    }

    pub fn run(&mut self) -> Result {
        self.sim.run()
    }
}

/// Used for tests where direct access to the database is necessary
pub async fn setup_db() -> Arc<Database> {
    let mut config = FlareConfig::default();
    config.store.storage.postgres_url = PG_URL.to_string();
    Arc::new(Database::new(config.store.storage).await)
}
