//! Round 3: the safegcd inverse against Fermat's on 200,000 random elements
//! of each field (`--ignored`; minutes in debug, seconds in release).
#![cfg(all(feature = "arithmetic", feature = "expose-field"))]

use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::{FieldElement, Scalar};

fn next(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

#[test]
#[ignore]
fn safegcd_matches_fermat_bulk() {
    let mut x = 0x0123_4567_89AB_CDEFu64;
    let (mut nf, mut ns) = (0u32, 0u32);
    for _ in 0..200_000 {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&next(&mut x).to_be_bytes());
        }
        if let Some(f) = Option::<FieldElement>::from(FieldElement::from_repr(b.into())) {
            if !bool::from(f.is_zero()) {
                assert_eq!(f.invert().unwrap(), f.invert_fermat());
                nf += 1;
            }
        }
        if let Some(s) = Option::<Scalar>::from(Scalar::from_repr(b.into())) {
            if !bool::from(s.is_zero()) {
                assert_eq!(s.invert().unwrap(), s.invert_fermat());
                ns += 1;
            }
        }
    }
    println!("field {nf} scalar {ns}");
    assert!(nf > 199_000 && ns > 199_000);
}
