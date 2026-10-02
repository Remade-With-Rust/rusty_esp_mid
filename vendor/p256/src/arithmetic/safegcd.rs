//! Constant-time modular inversion by Bernstein-Yang "safegcd" divsteps,
//! 30 at a time on signed 30-bit limbs (round 3, Janus vendored).
//!
//! A port of libsecp256k1's `modinv32` constant-time path
//! (`src/modinv32_impl.h`, MIT licence, Peter Dettman and Pieter Wuille;
//! the algorithm and its bound are in that repository's
//! `doc/safegcd_implementation.md`). Twenty rounds of thirty divsteps -- 600,
//! where 590 suffice for a modulus and an input below 2^256 -- each round a
//! 2x2 transition matrix applied to (f, g) and (d, e). No branch and no
//! memory access depends on the input. The inverse is unique, so the value
//! is the one Fermat's exponentiation gives; on a 32-bit core it is far
//! cheaper (the tests hold it to Fermat).

use elliptic_curve::bigint::U256;

/// Nine signed 30-bit limbs, little-endian: limbs 0-7 in `[0, 2^30)` when
/// normalised, limb 8 holding the rest.
type S30 = [i32; 9];

const M30: i32 = (u32::MAX >> 2) as i32;

/// A modulus and `modulus^-1 mod 2^30`.
pub(crate) struct ModInfo {
    modulus: S30,
    inv30: u32,
}

impl ModInfo {
    /// For an odd modulus below 2^256.
    pub(crate) const fn new(modulus: &U256) -> Self {
        let m = to_s30(modulus);
        // Newton: x <- x (2 - m x) doubles the correct low bits; m is odd,
        // so x = m is right to three bits; five steps give 96 > 30
        let m0 = m[0] as u32;
        let mut x = m0;
        let mut i = 0;
        while i < 5 {
            x = x.wrapping_mul(2u32.wrapping_sub(m0.wrapping_mul(x)));
            i += 1;
        }
        ModInfo {
            modulus: m,
            inv30: x & (M30 as u32),
        }
    }
}

/// The eight 32-bit words of `a`, little-endian, on either word size.
const fn words32(a: &U256) -> [u32; 8] {
    let w = a.as_words();
    let mut out = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        #[cfg(target_pointer_width = "32")]
        {
            out[i] = w[i] as u32;
        }
        #[cfg(target_pointer_width = "64")]
        {
            out[i] = (w[i / 2] >> (32 * (i % 2))) as u32;
        }
        i += 1;
    }
    out
}

/// `a` from eight 32-bit words, little-endian, on either word size.
const fn from_words32(w: &[u32; 8]) -> U256 {
    #[cfg(target_pointer_width = "32")]
    {
        let mut out = [0; 8];
        let mut i = 0;
        while i < 8 {
            out[i] = w[i] as _;
            i += 1;
        }
        U256::from_words(out)
    }
    #[cfg(target_pointer_width = "64")]
    {
        let mut out = [0; 4];
        let mut i = 0;
        while i < 4 {
            out[i] = (w[2 * i] as u64 | ((w[2 * i + 1] as u64) << 32)) as _;
            i += 1;
        }
        U256::from_words(out)
    }
}

const fn to_s30(a: &U256) -> S30 {
    let w = words32(a);
    let mut out = [0i32; 9];
    let mut i = 0;
    while i < 9 {
        // bits 30 i .. 30 i + 29
        let bit = 30 * i;
        let (word, shift) = (bit / 32, bit % 32);
        let mut v = (w[word] as u64) >> shift;
        if word + 1 < 8 {
            v |= (w[word + 1] as u64) << (32 - shift);
        }
        out[i] = if i < 8 {
            (v as u32 & M30 as u32) as i32
        } else {
            v as u32 as i32
        };
        i += 1;
    }
    out
}

const fn from_s30(a: &S30) -> U256 {
    // a normalised: limbs 0-7 in [0, 2^30), limb 8 in [0, 2^16)
    let mut w = [0u32; 8];
    let mut i = 0;
    while i < 9 {
        let v = a[i] as u32 as u64;
        let bit = 30 * i;
        let (word, shift) = (bit / 32, bit % 32);
        let x = v << shift;
        w[word] |= x as u32;
        if word + 1 < 8 {
            w[word + 1] |= (x >> 32) as u32;
        }
        i += 1;
    }
    from_words32(&w)
}

/// Thirty divsteps on the low limbs of f and g; returns the new zeta
/// (`-(delta + 1/2)`) and the transition matrix (u, v, q, r), scaled by 2^30.
const fn divsteps_30(mut zeta: i32, f0: u32, g0: u32) -> (i32, [i32; 4]) {
    let (mut u, mut v, mut q, mut r) = (1u32, 0u32, 0u32, 1u32);
    let (mut f, mut g) = (f0, g0);
    let mut i = 0;
    while i < 30 {
        // c1: all ones when zeta < 0 (delta > 0); c2: all ones when g is odd
        let mut c1 = (zeta >> 31) as u32;
        let c2 = (g & 1).wrapping_neg();
        // if delta > 0 and g odd: (f, g) = (g, (g - f) / 2) via negation
        let x = (f ^ c1).wrapping_sub(c1);
        let y = (u ^ c1).wrapping_sub(c1);
        let z = (v ^ c1).wrapping_sub(c1);
        g = g.wrapping_add(x & c2);
        q = q.wrapping_add(y & c2);
        r = r.wrapping_add(z & c2);
        c1 &= c2;
        zeta = (zeta ^ c1 as i32).wrapping_sub(1);
        f = f.wrapping_add(g & c1);
        u = u.wrapping_add(q & c1);
        v = v.wrapping_add(r & c1);
        g >>= 1;
        u <<= 1;
        v <<= 1;
        i += 1;
    }
    (zeta, [u as i32, v as i32, q as i32, r as i32])
}

/// (d, e) = t (d, e) / 2^30 mod the modulus, keeping both in range.
const fn update_de(d: &mut S30, e: &mut S30, t: &[i32; 4], m: &ModInfo) {
    let [u, v, q, r] = *t;
    let sd = d[8] >> 31;
    let se = e[8] >> 31;
    let mut md = (u & sd).wrapping_add(v & se);
    let mut me = (q & sd).wrapping_add(r & se);
    let (di, ei) = (d[0] as i64, e[0] as i64);
    let mut cd = (u as i64) * di + (v as i64) * ei;
    let mut ce = (q as i64) * di + (r as i64) * ei;
    // the modulus multiple that zeroes the bottom 30 bits
    md = md.wrapping_sub(
        (m.inv30.wrapping_mul(cd as u32).wrapping_add(md as u32) & M30 as u32) as i32,
    );
    me = me.wrapping_sub(
        (m.inv30.wrapping_mul(ce as u32).wrapping_add(me as u32) & M30 as u32) as i32,
    );
    cd += (m.modulus[0] as i64) * (md as i64);
    ce += (m.modulus[0] as i64) * (me as i64);
    cd >>= 30;
    ce >>= 30;
    let mut i = 1;
    while i < 9 {
        let (di, ei) = (d[i] as i64, e[i] as i64);
        cd += (u as i64) * di + (v as i64) * ei;
        ce += (q as i64) * di + (r as i64) * ei;
        cd += (m.modulus[i] as i64) * (md as i64);
        ce += (m.modulus[i] as i64) * (me as i64);
        d[i - 1] = (cd as i32) & M30;
        cd >>= 30;
        e[i - 1] = (ce as i32) & M30;
        ce >>= 30;
        i += 1;
    }
    d[8] = cd as i32;
    e[8] = ce as i32;
}

/// (f, g) = t (f, g) / 2^30 (exact).
const fn update_fg(f: &mut S30, g: &mut S30, t: &[i32; 4]) {
    let [u, v, q, r] = *t;
    let (fi, gi) = (f[0] as i64, g[0] as i64);
    let mut cf = ((u as i64) * fi + (v as i64) * gi) >> 30;
    let mut cg = ((q as i64) * fi + (r as i64) * gi) >> 30;
    let mut i = 1;
    while i < 9 {
        let (fi, gi) = (f[i] as i64, g[i] as i64);
        cf += (u as i64) * fi + (v as i64) * gi;
        cg += (q as i64) * fi + (r as i64) * gi;
        f[i - 1] = (cf as i32) & M30;
        cf >>= 30;
        g[i - 1] = (cg as i32) & M30;
        cg >>= 30;
        i += 1;
    }
    f[8] = cf as i32;
    g[8] = cg as i32;
}

/// `r` (in `(-2 modulus, modulus)`) negated when `sign < 0`, brought into
/// `[0, modulus)` with normalised limbs.
const fn normalize(r: &mut S30, sign: i32, m: &ModInfo) {
    // add the modulus if negative, then negate if asked
    let cond_add = r[8] >> 31;
    let cond_negate = sign >> 31;
    let mut i = 0;
    while i < 9 {
        r[i] = r[i].wrapping_add(m.modulus[i] & cond_add);
        r[i] = (r[i] ^ cond_negate).wrapping_sub(cond_negate);
        i += 1;
    }
    let mut i = 0;
    while i < 8 {
        r[i + 1] = r[i + 1].wrapping_add(r[i] >> 30);
        r[i] &= M30;
        i += 1;
    }
    // add the modulus again if still negative
    let cond_add = r[8] >> 31;
    let mut i = 0;
    while i < 9 {
        r[i] = r[i].wrapping_add(m.modulus[i] & cond_add);
        i += 1;
    }
    let mut i = 0;
    while i < 8 {
        r[i + 1] = r[i + 1].wrapping_add(r[i] >> 30);
        r[i] &= M30;
        i += 1;
    }
}

/// `x^-1 mod modulus` for `x` in `[0, modulus)`; zero for zero.
pub(crate) const fn invert(x: &U256, m: &ModInfo) -> U256 {
    let mut d = [0i32; 9];
    let mut e = [0i32; 9];
    e[0] = 1;
    let mut f = m.modulus;
    let mut g = to_s30(x);
    let mut zeta = -1i32;
    let mut i = 0;
    while i < 20 {
        let (z, t) = divsteps_30(zeta, f[0] as u32, g[0] as u32);
        zeta = z;
        update_de(&mut d, &mut e, &t, m);
        update_fg(&mut f, &mut g, &t);
        i += 1;
    }
    // g is 0 and f is +-1 (the gcd); d is +-x^-1
    normalize(&mut d, f[8], m);
    from_s30(&d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s30_round_trip() {
        for h in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            "123456789abcdef0fedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0",
        ] {
            let a = U256::from_be_hex(h);
            assert_eq!(from_s30(&to_s30(&a)), a);
        }
    }

    #[test]
    fn inv30() {
        for h in [
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        ] {
            let m = ModInfo::new(&U256::from_be_hex(h));
            assert_eq!(
                (m.modulus[0] as u32).wrapping_mul(m.inv30) & (M30 as u32),
                1
            );
        }
    }
}
