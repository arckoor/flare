use std::time::Duration;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use turmoil::{Builder, IpVersion, Result};

use crate::sim::FlareSimulation;

pub fn flare_test(f: impl FnOnce(&mut FlareSimulation<'_>) -> Result) -> Result {
    let timeout = Duration::from_secs(1000);
    flare_test_with_timeout(timeout, f)
}

pub fn flare_test_with_timeout(
    timeout: Duration,
    f: impl FnOnce(&mut FlareSimulation<'_>) -> Result,
) -> Result {
    let mut builder = Builder::new();
    builder
        .simulation_duration(timeout)
        .max_message_latency(Duration::from_millis(5));

    flare_test_with_builder(builder, f)
}

pub fn flare_test_with_builder(
    mut builder: Builder,
    f: impl FnOnce(&mut FlareSimulation<'_>) -> Result,
) -> Result {
    let mut master_rng = ChaChaRng::from_os_rng();

    let sim = builder
        .ip_version(IpVersion::V6)
        .enable_tokio_io()
        .rng_seed(master_rng.next_u64())
        .build();

    let mut flare_sim = FlareSimulation::new(sim);
    f(&mut flare_sim)
}
