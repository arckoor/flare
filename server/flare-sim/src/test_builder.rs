use std::time::Duration;

use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use rand_xoshiro::Xoshiro256PlusPlus;
use turmoil::{Builder, IpVersion, Result};

use crate::sim::FlareSimulation;

pub fn flare_test(f: impl FnOnce(&mut FlareSimulation<'_>) -> Result) -> Result {
    let timeout = Duration::from_secs(1000);
    flare_test_with_timeout(f, timeout)
}

pub fn flare_test_with_timeout(
    f: impl FnOnce(&mut FlareSimulation<'_>) -> Result,
    timeout: Duration,
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
    let mut master_rng = ChaChaRng::from_entropy();

    let turmoil_rng = Xoshiro256PlusPlus::from_rng(&mut master_rng).expect("Failed to seed RNG");
    let sim = builder
        .ip_version(IpVersion::V6)
        .enable_tokio_io()
        .build_with_rng(Box::new(turmoil_rng));

    let mut flare_sim = FlareSimulation::new(sim);
    f(&mut flare_sim)
}
