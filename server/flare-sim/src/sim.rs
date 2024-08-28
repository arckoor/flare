use std::future::Future;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use flare::config::FlareConfig;
use tempfile::TempDir;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::prelude::*;
use turmoil::{Result, Sim, ToIpAddr};

use flare;

pub const FLARE_SERVER: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
pub const FLARE_PORT: u16 = 9000;
pub const START_DELAY: Duration = Duration::from_secs(10);

pub struct FlareSimulation<'a> {
    pub working_dir: TempDir,
    pub sim: Sim<'a>,

    #[allow(unused)]
    tracing_subscriber_guard: DefaultGuard,
}

impl<'a> FlareSimulation<'a> {
    pub fn new(sim: Sim<'a>) -> Self {
        dotenv::dotenv().ok();

        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_test_writer())
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
            let base_url = dotenv::var("DATABASE_BASE").expect("DATABASE_BASE must be set");
            let db_url = format!("{}/flare-db-test", base_url);

            let mut config = FlareConfig::default();
            config.store.storage.base_path = path.clone();
            config.store.storage.database_url = db_url;
            config.server.port = FLARE_PORT;

            async move { flare::launch(config).await.map_err(|e| e.into()) }
        });
    }

    pub fn run(&mut self) -> Result {
        self.sim.run()
    }
}
