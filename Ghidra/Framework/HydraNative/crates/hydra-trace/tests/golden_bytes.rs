//! Output stays byte-compatible: the synthetic segments and the index digests they produce are
//! fixed values, so an optimisation of the write path cannot change them unnoticed.

use hydra_trace::raw;
use hydra_trace::store::Store;
use hydra_trace::synth::{self, Recipe};
use sha2::{Digest, Sha256};

#[test]
fn segments_and_digests_are_unchanged() {
    let mut segments = Sha256::new();
    let mut digests = Sha256::new();
    for recipe in [
        Recipe::Baseline,
        Recipe::Interleave,
        Recipe::Reuse,
        Recipe::Delayed,
        Recipe::Gap,
    ] {
        let mut store = Store::memory("golden").unwrap();
        for s in synth::generate(recipe, 11, 3000) {
            segments.update(&s.bytes);
            let scan = raw::scan(&s.bytes, &s.id);
            for (i, chunk) in scan.records.chunks(700).enumerate() {
                store.ingest(&s.id, (i * 700) as u64, chunk).unwrap();
            }
        }
        digests.update(store.digest().unwrap().as_bytes());
    }
    assert_eq!(
        format!("{:x}", segments.finalize()),
        "13cdc3f0d81f3193e9dfb2db4257730a7311d0b25db3fab30f487e9c3473f0f8"
    );
    assert_eq!(
        format!("{:x}", digests.finalize()),
        "430796382eff7ed4447ab652264c3ef86e9983c0f4b927a7e66f9cc4c8f42656"
    );
}
