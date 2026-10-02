//! 32-bit secp256r1 scalar field algorithms.
//!
//! **Janus vendored change (rusty_esp_mid, round 3, 2026-10-01).** As in
//! `field32.rs`: p256 0.13.2 ran this Barrett reduction on 64-bit limbs, so
//! a 32-bit CPU emulated every 128-bit product. Here it runs on 32-bit
//! words (b = 2^32, k = 8, mu = floor(2^512 / n) in nine words). Barrett's
//! answer after the two conditional subtractions is the canonical residue,
//! so it is the one the old code returned; `tests` hold it to that code,
//! kept below as `reference`.

use super::MODULUS;
use crate::U256;

/// floor(2^512 / n), little-endian 32-bit words (257 bits).
const MU32: [u32; 9] = [
    0xEEDF_9BFE,
    0x012F_FD85,
    0xDF1A_6C21,
    0x4319_0552,
    0xFFFF_FFFF,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
    0x0000_0000,
    0x0000_0001,
];

/// `acc + a * b + carry` as (low, high) words.
#[inline(always)]
const fn mac32(acc: u32, a: u32, b: u32, carry: u32) -> (u32, u32) {
    let w = (acc as u64) + (a as u64) * (b as u64) + (carry as u64);
    (w as u32, (w >> 32) as u32)
}

/// `a - b - borrow` with an all-ones-or-zero borrow in and out.
#[inline(always)]
const fn sbb32(a: u32, b: u32, borrow: u32) -> (u32, u32) {
    let w = (a as u64).wrapping_sub((b as u64) + ((borrow >> 31) as u64));
    (w as u32, (w >> 32) as u32)
}

/// Nine words less n when that does not go below zero (constant time).
#[inline(always)]
const fn subtract_n_if_necessary(r: [u32; 9]) -> [u32; 9] {
    let n = MODULUS.as_words();
    let mut w = [0u32; 9];
    let mut borrow = 0u32;
    let mut j = 0;
    while j < 9 {
        let nj = if j < 8 { n[j] } else { 0 };
        let (s, b) = sbb32(r[j], nj, borrow);
        w[j] = s;
        borrow = b;
        j += 1;
    }
    // borrow all-ones: r < n, keep r
    let mut out = [0u32; 9];
    let mut j = 0;
    while j < 9 {
        out[j] = (r[j] & borrow) | (w[j] & !borrow);
        j += 1;
    }
    out
}

/// Barrett reduction of the 512-bit `hi:lo` modulo n (HAC 14.42, b = 2^32).
#[inline]
pub(super) const fn barrett_reduce(lo: U256, hi: U256) -> U256 {
    let lo = lo.as_words();
    let hi = hi.as_words();
    let mut a = [0u32; 16];
    let mut i = 0;
    while i < 8 {
        a[i] = lo[i];
        a[i + 8] = hi[i];
        i += 1;
    }

    // q3 = floor(floor(a / b^7) * mu / b^9): the product's words 9..=17
    let mut q2 = [0u32; 18];
    let mut i = 0;
    while i < 9 {
        let q1i = a[7 + i];
        let mut c = 0u32;
        let mut j = 0;
        while j < 9 {
            let (s, cc) = mac32(q2[i + j], q1i, MU32[j], c);
            q2[i + j] = s;
            c = cc;
            j += 1;
        }
        q2[i + 9] = c;
        i += 1;
    }

    // r2 = q3 * n mod b^9
    let n = MODULUS.as_words();
    let mut r2 = [0u32; 9];
    let mut i = 0;
    while i < 9 {
        let q3i = q2[9 + i];
        let mut c = 0u32;
        let mut j = 0;
        while i + j < 9 {
            let nj = if j < 8 { n[j] } else { 0 };
            let (s, cc) = mac32(r2[i + j], q3i, nj, c);
            r2[i + j] = s;
            c = cc;
            j += 1;
        }
        i += 1;
    }

    // r = a mod b^9 - r2, modulo b^9 (a borrow out of the top is b^9 added)
    let mut r = [0u32; 9];
    let mut borrow = 0u32;
    let mut j = 0;
    while j < 9 {
        let (s, b) = sbb32(a[j], r2[j], borrow);
        r[j] = s;
        borrow = b;
        j += 1;
    }

    // r < 3n: at most two subtractions
    let r = subtract_n_if_necessary(r);
    let r = subtract_n_if_necessary(r);
    U256::from_words([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]])
}

/// p256 0.13.2's own 32-bit file, verbatim but for the module wrapper.
#[cfg(test)]
#[allow(dead_code, clippy::all)]
mod reference {
    use super::super::{MODULUS, MU};

    use crate::{
        arithmetic::util::{adc, mac, sbb},
        U256,
    };

    /// Barrett Reduction
    ///
    /// The general algorithm is:
    /// ```text
    /// p = n = order of group
    /// b = 2^64 = 64bit machine word
    /// k = 4
    /// a \in [0, 2^512]
    /// mu := floor(b^{2k} / p)
    /// q1 := floor(a / b^{k - 1})
    /// q2 := q1 * mu
    /// q3 := <- floor(a / b^{k - 1})
    /// r1 := a mod b^{k + 1}
    /// r2 := q3 * m mod b^{k + 1}
    /// r := r1 - r2
    ///
    /// if r < 0: r := r + b^{k + 1}
    /// while r >= p: do r := r - p (at most twice)
    /// ```
    ///
    /// References:
    /// - Handbook of Applied Cryptography, Chapter 14
    ///   Algorithm 14.42
    ///   http://cacr.uwaterloo.ca/hac/about/chap14.pdf
    ///
    /// - Efficient and Secure Elliptic Curve Cryptography Implementation of Curve P-256
    ///   Algorithm 6) Barrett Reduction modulo p
    ///   https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn barrett_reduce(lo: U256, hi: U256) -> U256 {
        let lo = u256_to_u64x4(lo);
        let hi = u256_to_u64x4(hi);
        let a0 = lo[0];
        let a1 = lo[1];
        let a2 = lo[2];
        let a3 = lo[3];
        let a4 = hi[0];
        let a5 = hi[1];
        let a6 = hi[2];
        let a7 = hi[3];
        let q1: [u64; 5] = [a3, a4, a5, a6, a7];
        let q3 = q1_times_mu_shift_five(&q1);

        let r1: [u64; 5] = [a0, a1, a2, a3, a4];
        let r2: [u64; 5] = q3_times_n_keep_five(&q3);
        let r: [u64; 5] = sub_inner_five(r1, r2);

        // Result is in range (0, 3*n - 1),
        // and 90% of the time, no subtraction will be needed.
        let r = subtract_n_if_necessary(r[0], r[1], r[2], r[3], r[4]);
        let r = subtract_n_if_necessary(r[0], r[1], r[2], r[3], r[4]);

        U256::from_words([
            (r[0] & 0xFFFFFFFF) as u32,
            (r[0] >> 32) as u32,
            (r[1] & 0xFFFFFFFF) as u32,
            (r[1] >> 32) as u32,
            (r[2] & 0xFFFFFFFF) as u32,
            (r[2] >> 32) as u32,
            (r[3] & 0xFFFFFFFF) as u32,
            (r[3] >> 32) as u32,
        ])
    }

    const fn q1_times_mu_shift_five(q1: &[u64; 5]) -> [u64; 5] {
        // Schoolbook multiplication.

        let (_w0, carry) = mac(0, q1[0], MU[0], 0);
        let (w1, carry) = mac(0, q1[0], MU[1], carry);
        let (w2, carry) = mac(0, q1[0], MU[2], carry);
        let (w3, carry) = mac(0, q1[0], MU[3], carry);
        let (w4, w5) = mac(0, q1[0], MU[4], carry);

        let (_w1, carry) = mac(w1, q1[1], MU[0], 0);
        let (w2, carry) = mac(w2, q1[1], MU[1], carry);
        let (w3, carry) = mac(w3, q1[1], MU[2], carry);
        let (w4, carry) = mac(w4, q1[1], MU[3], carry);
        let (w5, w6) = mac(w5, q1[1], MU[4], carry);

        let (_w2, carry) = mac(w2, q1[2], MU[0], 0);
        let (w3, carry) = mac(w3, q1[2], MU[1], carry);
        let (w4, carry) = mac(w4, q1[2], MU[2], carry);
        let (w5, carry) = mac(w5, q1[2], MU[3], carry);
        let (w6, w7) = mac(w6, q1[2], MU[4], carry);

        let (_w3, carry) = mac(w3, q1[3], MU[0], 0);
        let (w4, carry) = mac(w4, q1[3], MU[1], carry);
        let (w5, carry) = mac(w5, q1[3], MU[2], carry);
        let (w6, carry) = mac(w6, q1[3], MU[3], carry);
        let (w7, w8) = mac(w7, q1[3], MU[4], carry);

        let (_w4, carry) = mac(w4, q1[4], MU[0], 0);
        let (w5, carry) = mac(w5, q1[4], MU[1], carry);
        let (w6, carry) = mac(w6, q1[4], MU[2], carry);
        let (w7, carry) = mac(w7, q1[4], MU[3], carry);
        let (w8, w9) = mac(w8, q1[4], MU[4], carry);

        // let q2 = [_w0, _w1, _w2, _w3, _w4, w5, w6, w7, w8, w9];
        [w5, w6, w7, w8, w9]
    }

    const fn q3_times_n_keep_five(q3: &[u64; 5]) -> [u64; 5] {
        // Schoolbook multiplication.

        let modulus = u256_to_u64x4(MODULUS);

        let (w0, carry) = mac(0, q3[0], modulus[0], 0);
        let (w1, carry) = mac(0, q3[0], modulus[1], carry);
        let (w2, carry) = mac(0, q3[0], modulus[2], carry);
        let (w3, carry) = mac(0, q3[0], modulus[3], carry);
        let (w4, _) = mac(0, q3[0], 0, carry);

        let (w1, carry) = mac(w1, q3[1], modulus[0], 0);
        let (w2, carry) = mac(w2, q3[1], modulus[1], carry);
        let (w3, carry) = mac(w3, q3[1], modulus[2], carry);
        let (w4, _) = mac(w4, q3[1], modulus[3], carry);

        let (w2, carry) = mac(w2, q3[2], modulus[0], 0);
        let (w3, carry) = mac(w3, q3[2], modulus[1], carry);
        let (w4, _) = mac(w4, q3[2], modulus[2], carry);

        let (w3, carry) = mac(w3, q3[3], modulus[0], 0);
        let (w4, _) = mac(w4, q3[3], modulus[1], carry);

        let (w4, _) = mac(w4, q3[4], modulus[0], 0);

        [w0, w1, w2, w3, w4]
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    const fn sub_inner_five(l: [u64; 5], r: [u64; 5]) -> [u64; 5] {
        let (w0, borrow) = sbb(l[0], r[0], 0);
        let (w1, borrow) = sbb(l[1], r[1], borrow);
        let (w2, borrow) = sbb(l[2], r[2], borrow);
        let (w3, borrow) = sbb(l[3], r[3], borrow);
        let (w4, _borrow) = sbb(l[4], r[4], borrow);

        // If underflow occurred on the final limb - don't care (= add b^{k+1}).
        [w0, w1, w2, w3, w4]
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    const fn subtract_n_if_necessary(r0: u64, r1: u64, r2: u64, r3: u64, r4: u64) -> [u64; 5] {
        let modulus = u256_to_u64x4(MODULUS);

        let (w0, borrow) = sbb(r0, modulus[0], 0);
        let (w1, borrow) = sbb(r1, modulus[1], borrow);
        let (w2, borrow) = sbb(r2, modulus[2], borrow);
        let (w3, borrow) = sbb(r3, modulus[3], borrow);
        let (w4, borrow) = sbb(r4, 0, borrow);

        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the
        // modulus.
        let (w0, carry) = adc(w0, modulus[0] & borrow, 0);
        let (w1, carry) = adc(w1, modulus[1] & borrow, carry);
        let (w2, carry) = adc(w2, modulus[2] & borrow, carry);
        let (w3, carry) = adc(w3, modulus[3] & borrow, carry);
        let (w4, _carry) = adc(w4, 0, carry);

        [w0, w1, w2, w3, w4]
    }

    // TODO(tarcieri): replace this with proper 32-bit arithmetic
    #[inline]
    const fn u256_to_u64x4(u256: U256) -> [u64; 4] {
        let words = u256.as_words();

        [
            (words[0] as u64) | ((words[1] as u64) << 32),
            (words[2] as u64) | ((words[3] as u64) << 32),
            (words[4] as u64) | ((words[5] as u64) << 32),
            (words[6] as u64) | ((words[7] as u64) << 32),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn mu_is_the_64_bit_mu() {
        let mu = super::super::MU;
        for (i, w) in mu.iter().enumerate() {
            let lo = MU32.get(2 * i).copied().unwrap_or(0) as u64;
            let hi = MU32.get(2 * i + 1).copied().unwrap_or(0) as u64;
            assert_eq!(*w, lo | (hi << 32), "word {i}");
        }
    }

    #[test]
    fn edges_match_the_u64_reference() {
        let n = *MODULUS.as_words();
        let mut nm1 = n;
        nm1[0] -= 1;
        let edges: [[u32; 8]; 6] = [
            [0; 8],
            [1, 0, 0, 0, 0, 0, 0, 0],
            n,
            nm1,
            [0xFFFF_FFFF; 8],
            [0, 0, 0, 0, 0, 0, 0, 0x8000_0000],
        ];
        for lo in edges {
            for hi in edges {
                let (l, h) = (U256::from_words(lo), U256::from_words(hi));
                assert_eq!(barrett_reduce(l, h), reference::barrett_reduce(l, h));
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20_000))]
        #[test]
        fn barrett_matches_the_u64_reference(lo in any::<[u32; 8]>(), hi in any::<[u32; 8]>()) {
            let (l, h) = (U256::from_words(lo), U256::from_words(hi));
            prop_assert_eq!(barrett_reduce(l, h), reference::barrett_reduce(l, h));
        }
    }
}
