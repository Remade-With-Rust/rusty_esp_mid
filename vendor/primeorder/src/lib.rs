#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

pub mod point_arithmetic;

mod affine;
#[cfg(feature = "dev")]
mod dev;
mod field;
mod projective;

pub use crate::{affine::AffinePoint, projective::ProjectivePoint};
pub use elliptic_curve::{
    self, generic_array, point::Double, Field, FieldBytes, PrimeCurve, PrimeField,
};

use elliptic_curve::CurveArithmetic;

/// Parameters for elliptic curves of prime order which can be described by the
/// short Weierstrass equation.
pub trait PrimeCurveParams:
    PrimeCurve
    + CurveArithmetic
    + CurveArithmetic<AffinePoint = AffinePoint<Self>>
    + CurveArithmetic<ProjectivePoint = ProjectivePoint<Self>>
{
    /// Base field element type.
    // TODO(tarcieri): add `Invert` bound
    type FieldElement: PrimeField<Repr = FieldBytes<Self>> + 'static;

    /// [Point arithmetic](point_arithmetic) implementation, might be optimized for this specific curve
    type PointArithmetic: point_arithmetic::PointArithmetic<Self>;

    /// Coefficient `a` in the curve equation.
    const EQUATION_A: Self::FieldElement;

    /// Coefficient `b` in the curve equation.
    const EQUATION_B: Self::FieldElement;

    /// Generator point's affine coordinates: (x, y).
    const GENERATOR: (Self::FieldElement, Self::FieldElement);

    /// **Janus vendored (round 3).** A fixed-base table for the generator:
    /// `[i][j - 1]` is `j * 32^i * G`, affine, `j` up to 16. With one, `[k] G`
    /// is 52 signed digits, 52 constant-time lookups and mixed additions and
    /// no doublings, in place
    /// of the windowed double-and-add (the upstream TODO, "precomputed
    /// basepoint tables"). `None` keeps the upstream path.
    const GENERATOR_TABLE: Option<&'static GeneratorTable<Self>> = None;
}

/// The width of a [`GeneratorTable`]'s windows, in bits (round 3): 5, read as
/// signed digits in `[-16, 16]`, so 52 rows of 16 multiples (53 KB for
/// P-256). Every lookup reads a whole row from flash, so the table's size
/// is the comb's cost as much as its additions are: unsigned 4-bit windows
/// (64 rows of 15, 61 KB) and unsigned 5-bit ones (52 of 31, 103 KB) were
/// both slower.
pub const TABLE_WINDOW: usize = 5;
/// Rows in a [`GeneratorTable`]: windows enough for 256 bits.
pub const TABLE_ROWS: usize = (256 + TABLE_WINDOW - 1) / TABLE_WINDOW;
/// Multiples in a [`GeneratorTable`] row: the digit's magnitude, 1 to 16.
pub const TABLE_ENTRIES: usize = 1 << (TABLE_WINDOW - 1);

/// A fixed-base table for a 256-bit curve's generator, [`TABLE_WINDOW`]-bit
/// signed windows: [`TABLE_ROWS`] rows of the [`TABLE_ENTRIES`] positive
/// multiples (round 3).
pub type GeneratorTable<C> = [[(
    <C as PrimeCurveParams>::FieldElement,
    <C as PrimeCurveParams>::FieldElement,
); TABLE_ENTRIES]; TABLE_ROWS];
