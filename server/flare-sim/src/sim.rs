use std::env;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use flare::api::api_params::AddGroup;
use tempfile::TempDir;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::prelude::*;
use turmoil::{Result, Sim, ToIpAddr};

use crate::helpers::{self};
use flare;
use flare::config::FlareConfig;

pub const FLARE_SERVER: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
pub const FLARE_PORT: u16 = 9000;
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
            let base_url = env::var("DATABASE_BASE").expect("DATABASE_BASE must be set");
            let db_url = format!("{}/flare-db-test", base_url);

            let mut config = FlareConfig::default();
            config.store.storage.base_path = path.clone();
            config.store.storage.database_url = db_url;
            config.server.port = FLARE_PORT;
            config.store.storage.admin.github_id = None;
            config.store.storage.admin.discord_id = Some("admin".to_string());

            async move { flare::launch(config).await.map_err(|e| e.into()) }
        });
    }

    pub fn create_basic_scenario(&mut self) {
        self.start_api();

        self.client("setup-client", async move {
            let mut client = helpers::Http::new_with_cookies(true, None);
            helpers::wait_for_api(&client).await;

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
        self.client("group-users-client", async move {
            let (mut owner_client, _) = helpers::get_client(owner, false).await.unwrap();

            let group = helpers::add_group(&owner_client, AddGroup { name: group_name })
                .await
                .unwrap();

            helpers::refresh(&mut owner_client).await.unwrap();

            for user in users {
                let (user_client, user_id) = helpers::get_client(user, true).await.unwrap();

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
