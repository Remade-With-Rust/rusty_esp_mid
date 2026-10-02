//! Janus vendored (round 3): the fixed-base table path against the generic
//! windowed multiply. The generic path is reached through a generator whose
//! projective coordinates are not the constant's (2G - G), so the table is
//! never consulted there.
#![cfg(feature = "arithmetic")]

use elliptic_curve::group::Group;
use elliptic_curve::ops::MulByGenerator;
use p256::{ProjectivePoint, Scalar};
use proptest::prelude::*;

fn g_alt() -> ProjectivePoint {
    let g = ProjectivePoint::GENERATOR;
    g.double() - g
}

#[test]
fn every_multiple_in_four_rows_is_the_generic_one() {
    let alt = g_alt();
    for row in [0u32, 1, 25, 51] {
        let mut base = Scalar::ONE;
        for _ in 0..row {
            base *= Scalar::from(32u64);
        }
        // 1..=16 straight from the row; 17..=31 as a negative digit and a carry
        for j in 1..=31u64 {
            let k = base * Scalar::from(j);
            assert_eq!(
                ProjectivePoint::mul_by_generator(&k).to_affine(),
                (alt * k).to_affine(),
                "row {row} multiple {j}"
            );
        }
    }
}

#[test]
fn zero_one_and_minus_one() {
    let alt = g_alt();
    for k in [
        Scalar::ZERO,
        Scalar::ONE,
        -Scalar::ONE,
        Scalar::from(32u64),
        Scalar::from(16u64),
        Scalar::from(17u64),
        Scalar::from(31u64),
        Scalar::from(33u64),
        Scalar::from(0x7FFF_FFFF_FFFF_FFFFu64),
        -Scalar::from(17u64),
    ] {
        assert_eq!(
            ProjectivePoint::mul_by_generator(&k).to_affine(),
            (alt * k).to_affine()
        );
        assert_eq!(
            (ProjectivePoint::generator() * k).to_affine(),
            (alt * k).to_affine()
        );
    }
    assert!(bool::from(
        ProjectivePoint::mul_by_generator(&Scalar::ZERO).is_identity()
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn random_scalars(bytes in any::<[u8; 32]>()) {
        let k = <Scalar as elliptic_curve::ops::Reduce<p256::U256>>::reduce_bytes(&bytes.into());
        let want = (g_alt() * k).to_affine();
        prop_assert_eq!(ProjectivePoint::mul_by_generator(&k).to_affine(), want);
        prop_assert_eq!((ProjectivePoint::generator() * k).to_affine(), want);
    }
}
