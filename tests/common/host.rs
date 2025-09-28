use crate::common::manifest::load_example_manifest;
use captra::HostState;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

/// Build a [`HostState`] with a fixed seed and a fresh [`SigningKey`] (`OsRng`).
/// # Panics
#[must_use]
pub fn make_host_with_seed(seed: u64) -> HostState {
    let manifest = load_example_manifest();
    let mut csprng = OsRng;
    let keypair = SigningKey::generate(&mut csprng);
    HostState::new(manifest, seed, keypair)
}
