#![no_main]

use libfuzzer_sys::fuzz_target;

macro_rules! roundtrip {
    ($ty:ty, $data:expr) => {
        if let Ok(value) = <$ty>::from_bytes($data) {
            let encoded = value.to_bytes();
            let decoded = <$ty>::from_bytes(&encoded).expect("re-encoded proof must decode");
            assert_eq!(value, decoded, "canonical round-trip changed the value");
        }
    };
}

fuzz_target!(|data: &[u8]| {
    roundtrip!(z0p::air::Proof, data);
    roundtrip!(z0p::basefold::Commitment, data);
    roundtrip!(z0p::basefold::Proof, data);
    roundtrip!(z0p::fold::IvcProof, data);
    roundtrip!(z0p::fri::Commitment, data);
    roundtrip!(z0p::fri::Proof, data);
    roundtrip!(z0p::gemini::Commitment, data);
    roundtrip!(z0p::gemini::Proof, data);
    roundtrip!(z0p::lookup::Proof, data);
    roundtrip!(z0p::lookup_pcs::Commitments, data);
    roundtrip!(z0p::lookup_pcs::Proof, data);
    roundtrip!(z0p::range::Proof, data);
    roundtrip!(z0p::recursion::Proof, data);
    roundtrip!(z0p::sumcheck::Proof, data);
    roundtrip!(z0p::table::Proof, data);
    roundtrip!(z0p::upcs::Commitment, data);
    roundtrip!(z0p::upcs::Proof, data);
    roundtrip!(z0p::vm::Proof, data);
});
