use captra::{CapabilityManifest, load_manifest};

/// Load the example manifest bundled with the repo.
/// # Panics
#[inline]
#[must_use]
pub fn load_example_manifest() -> CapabilityManifest {
    load_manifest("examples/manifest.json").expect("examples/manifest.json must exists")
}
