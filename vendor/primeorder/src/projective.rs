//! Projective curve points.

#![allow(clippy::needless_range_loop, clippy::op_ref)]

use crate::{point_arithmetic::PointArithmetic, AffinePoint, Field, PrimeCurveParams};
use core::{
    borrow::Borrow,
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::{
    bigint::{ArrayEncoding, Integer},
    generic_array::ArrayLength,
    group::{
        self,
        cofactor::CofactorGroup,
        prime::{PrimeCurve, PrimeGroup},
        Group, GroupEncoding,
    },
    ops::{BatchInvert, Invert, LinearCombination, MulByGenerator},
    point::Double,
    rand_core::RngCore,
    sec1::{
        CompressedPoint, EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint,
        UncompressedPointSize,
    },
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    BatchNormalize, Error, FieldBytes, FieldBytesSize, PublicKey, Result, Scalar,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Point on a Weierstrass curve in projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint<C: PrimeCurveParams> {
    pub(crate) x: C::FieldElement,
    pub(crate) y: C::FieldElement,
    pub(crate) z: C::FieldElement,
}

impl<C> ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    /// Additive identity of the group a.k.a. the point at infinity.
    pub const IDENTITY: Self = Self {
        x: C::FieldElement::ZERO,
        y: C::FieldElement::ONE,
        z: C::FieldElement::ZERO,
    };

    /// Base point of the curve.
    pub const GENERATOR: Self = Self {
        x: C::GENERATOR.0,
        y: C::GENERATOR.1,
        z: C::FieldElement::ONE,
    };

    /// Returns the affine representation of this point, or `None` if it is the identity.
    pub fn to_affine(&self) -> AffinePoint<C> {
        <C::FieldElement as Field>::invert(&self.z)
            .map(|zinv| self.to_affine_internal(zinv))
            .unwrap_or(AffinePoint::IDENTITY)
    }

    pub(super) fn to_affine_internal(self, zinv: C::FieldElement) -> AffinePoint<C> {
        AffinePoint {
            x: self.x * &zinv,
            y: self.y * &zinv,
            infinity: 0,
        }
    }

    /// Returns `-self`.
    pub fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }

    /// Returns `self + other`.
    pub fn add(&self, other: &Self) -> Self {
        C::PointArithmetic::add(self, other)
    }

    /// Returns `self + other`.
    fn add_mixed(&self, other: &AffinePoint<C>) -> Self {
        C::PointArithmetic::add_mixed(self, other)
    }

    /// Returns `self - other`.
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    /// Returns `self - other`.
    fn sub_mixed(&self, other: &AffinePoint<C>) -> Self {
        self.add_mixed(&other.neg())
    }

    /// `[k] G` from the curve's fixed-base table (round 3): the scalar as
    /// signed [`TABLE_WINDOW`](crate::TABLE_WINDOW)-bit digits (a window
    /// above 16 becomes `w - 32` and carries one into the next), and for
    /// each the multiple `|d| * 32^i * G` chosen in constant time (every
    /// entry is read), negated in constant time when `d < 0`, and one mixed
    /// addition (`d = 0` adds the identity). The same point as the windowed
    /// multiply, every time.
    fn mul_by_table(table: &crate::GeneratorTable<C>, k: &Scalar<C>) -> Self {
        let k = Into::<C::Uint>::into(*k).to_le_byte_array();
        let mut q = Self::IDENTITY;
        let mut carry = 0u8;
        for (i, row) in table.iter().enumerate() {
            // window i: bits W i .. W i + W - 1 of the little-endian scalar
            // (which bytes is public; the bits are masked, never branched on)
            let bit = crate::TABLE_WINDOW * i;
            let (byte, shift) = (bit >> 3, bit & 7);
            let lo = k[byte] as u16;
            let hi = if byte + 1 < k.len() {
                k[byte + 1] as u16
            } else {
                0
            };
            // w in 0..=32; above 16 the digit is w - 32 and one carries
            let w = ((((hi << 8) | lo) >> shift) as u8 & 31) + carry;
            let neg = (16u8.wrapping_sub(w) >> 7) & 1;
            carry = neg;
            let abs = w ^ ((w ^ 32u8.wrapping_sub(w)) & neg.wrapping_neg());
            let (mut x, mut y) = row[0];
            for (j, entry) in row.iter().enumerate().skip(1) {
                let c = Choice::from((((abs as usize) ^ (j + 1)).wrapping_sub(1) >> 8) as u8 & 1);
                x.conditional_assign(&entry.0, c);
                y.conditional_assign(&entry.1, c);
            }
            let ny = -y;
            y.conditional_assign(&ny, Choice::from(neg));
            let zero = (((abs as usize).wrapping_sub(1) >> 8) as u8) & 1;
            q = q.add_mixed(&AffinePoint {
                x,
                y,
                infinity: zero,
            });
        }
        q
    }

    /// Whether `self` is the generator constant itself (public data: a
    /// comparison of the representation, not of the point's class).
    fn is_generator_constant(&self) -> bool {
        bool::from(
            self.x.ct_eq(&C::GENERATOR.0)
                & self.y.ct_eq(&C::GENERATOR.1)
                & self.z.ct_eq(&C::FieldElement::ONE),
        )
    }

    /// Returns `[k] self`.
    fn mul(&self, k: &Scalar<C>) -> Self
    where
        Self: Double,
    {
        // the generator through its table (round 3): `PublicKey::from_secret_scalar`
        // multiplies `generator()` by the scalar, not `mul_by_generator`
        if let Some(table) = C::GENERATOR_TABLE {
            if self.is_generator_constant() {
                return Self::mul_by_table(table, k);
            }
        }
        let k = Into::<C::Uint>::into(*k).to_le_byte_array();

        let mut pc = [Self::default(); 16];
        pc[0] = Self::IDENTITY;
        pc[1] = *self;

        for i in 2..16 {
            pc[i] = if i % 2 == 0 {
                Double::double(&pc[i / 2])
            } else {
                pc[i - 1].add(self)
            };
        }

        let mut q = Self::IDENTITY;
        let mut pos = C::Uint::BITS - 4;

        loop {
            let slot = (k[pos >> 3] >> (pos & 7)) & 0xf;

            let mut t = ProjectivePoint::IDENTITY;

            for i in 1..16 {
                t.conditional_assign(
                    &pc[i],
                    Choice::from(((slot as usize ^ i).wrapping_sub(1) >> 8) as u8 & 1),
                );
            }

            q = q.add(&t);

            if pos == 0 {
                break;
            }

            q = Double::double(&Double::double(&Double::double(&Double::double(&q))));
            pos -= 4;
        }

        q
    }
}

impl<C> CofactorGroup for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    FieldBytes<C>: Copy,
    FieldBytesSize<C>: ModulusSize,
    CompressedPoint<C>: Copy,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
    type Subgroup = Self;

    fn clear_cofactor(&self) -> Self::Subgroup {
        *self
    }

    fn into_subgroup(self) -> CtOption<Self> {
        CtOption::new(self, 1.into())
    }

    fn is_torsion_free(&self) -> Choice {
        1.into()
    }
}

impl<C> ConditionallySelectable for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: C::FieldElement::conditional_select(&a.x, &b.x, choice),
            y: C::FieldElement::conditional_select(&a.y, &b.y, choice),
            z: C::FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl<C> ConstantTimeEq for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_affine().ct_eq(&other.to_affine())
    }
}

impl<C> Default for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl<C> DefaultIsZeroes for ProjectivePoint<C> where C: PrimeCurveParams {}

impl<C: PrimeCurveParams> Double for ProjectivePoint<C> {
    fn double(&self) -> Self {
        C::PointArithmetic::double(self)
    }
}

impl<C> Eq for ProjectivePoint<C> where C: PrimeCurveParams {}

impl<C> From<AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn from(p: AffinePoint<C>) -> Self {
        let projective = ProjectivePoint {
            x: p.x,
            y: p.y,
            z: C::FieldElement::ONE,
        };
        Self::conditional_select(&projective, &Self::IDENTITY, p.is_identity())
    }
}

impl<C> From<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn from(p: &AffinePoint<C>) -> Self {
        Self::from(*p)
    }
}

impl<C> From<PublicKey<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn from(public_key: PublicKey<C>) -> ProjectivePoint<C> {
        AffinePoint::from(public_key).into()
    }
}

impl<C> From<&PublicKey<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn from(public_key: &PublicKey<C>) -> ProjectivePoint<C> {
        AffinePoint::<C>::from(public_key).into()
    }
}

impl<C> FromEncodedPoint<C> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
    FieldBytes<C>: Copy,
    FieldBytesSize<C>: ModulusSize,
    CompressedPoint<C>: Copy,
{
    fn from_encoded_point(p: &EncodedPoint<C>) -> CtOption<Self> {
        AffinePoint::<C>::from_encoded_point(p).map(Self::from)
    }
}

impl<C> Group for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
{
    type Scalar = Scalar<C>;

    fn random(mut rng: impl RngCore) -> Self {
        Self::GENERATOR * <Scalar<C> as Field>::random(&mut rng)
    }

    fn identity() -> Self {
        Self::IDENTITY
    }

    fn generator() -> Self {
        Self::GENERATOR
    }

    fn is_identity(&self) -> Choice {
        self.ct_eq(&Self::IDENTITY)
    }

    #[must_use]
    fn double(&self) -> Self {
        Double::double(self)
    }
}

impl<C> GroupEncoding for ProjectivePoint<C>
where
    C: PrimeCurveParams,
    FieldBytes<C>: Copy,
    FieldBytesSize<C>: ModulusSize,
    CompressedPoint<C>: Copy,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
    type Repr = CompressedPoint<C>;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <AffinePoint<C> as GroupEncoding>::from_bytes(bytes).map(Into::into)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.to_affine().to_bytes()
    }
}

impl<C> group::Curve for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
{
    type AffineRepr = AffinePoint<C>;

    fn to_affine(&self) -> AffinePoint<C> {
        ProjectivePoint::to_affine(self)
    }

    // TODO(tarcieri): re-enable when we can add `Invert` bounds on `FieldElement`
    // #[cfg(feature = "alloc")]
    // #[inline]
    // fn batch_normalize(projective: &[Self], affine: &mut [Self::AffineRepr]) {
    //     assert_eq!(projective.len(), affine.len());
    //     let mut zs = vec![C::FieldElement::ONE; projective.len()];
    //     batch_normalize_generic(projective, zs.as_mut_slice(), affine);
    // }
}

impl<const N: usize, C> BatchNormalize<[ProjectivePoint<C>; N]> for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    C::FieldElement: Invert<Output = CtOption<C::FieldElement>>,
{
    type Output = [Self::AffineRepr; N];

    #[inline]
    fn batch_normalize(points: &[Self; N]) -> [Self::AffineRepr; N] {
        let mut zs = [C::FieldElement::ONE; N];
        let mut affine_points = [C::AffinePoint::IDENTITY; N];
        batch_normalize_generic(points, &mut zs, &mut affine_points);
        affine_points
    }
}

#[cfg(feature = "alloc")]
impl<C> BatchNormalize<[ProjectivePoint<C>]> for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    C::FieldElement: Invert<Output = CtOption<C::FieldElement>>,
{
    type Output = Vec<Self::AffineRepr>;

    #[inline]
    fn batch_normalize(points: &[Self]) -> Vec<Self::AffineRepr> {
        let mut zs = vec![C::FieldElement::ONE; points.len()];
        let mut affine_points = vec![AffinePoint::IDENTITY; points.len()];
        batch_normalize_generic(points, zs.as_mut_slice(), &mut affine_points);
        affine_points
    }
}

/// Generic implementation of batch normalization.
fn batch_normalize_generic<C, P, Z, O>(points: &P, zs: &mut Z, out: &mut O)
where
    C: PrimeCurveParams,
    C::FieldElement: BatchInvert<Z>,
    C::ProjectivePoint: Double,
    P: AsRef<[ProjectivePoint<C>]> + ?Sized,
    Z: AsMut<[C::FieldElement]> + ?Sized,
    O: AsMut<[AffinePoint<C>]> + ?Sized,
{
    let points = points.as_ref();
    let out = out.as_mut();

    for i in 0..points.len() {
        // Even a single zero value will fail inversion for the entire batch.
        // Put a dummy value (above `FieldElement::ONE`) so inversion succeeds
        // and treat that case specially later-on.
        zs.as_mut()[i].conditional_assign(&points[i].z, !points[i].z.ct_eq(&C::FieldElement::ZERO));
    }

    // This is safe to unwrap since we assured that all elements are non-zero
    let zs_inverses = <C::FieldElement as BatchInvert<Z>>::batch_invert(zs).unwrap();

    for i in 0..out.len() {
        // If the `z` coordinate is non-zero, we can use it to invert;
        // otherwise it defaults to the `IDENTITY` value.
        out[i] = C::AffinePoint::conditional_select(
            &points[i].to_affine_internal(zs_inverses.as_ref()[i]),
            &C::AffinePoint::IDENTITY,
            points[i].z.ct_eq(&C::FieldElement::ZERO),
        );
    }
}

impl<C> LinearCombination for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
{
}

impl<C> MulByGenerator for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
{
    fn mul_by_generator(scalar: &Self::Scalar) -> Self {
        match C::GENERATOR_TABLE {
            Some(table) => Self::mul_by_table(table, scalar),
            None => Self::generator() * scalar,
        }
    }
}

impl<C> PrimeGroup for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    FieldBytes<C>: Copy,
    FieldBytesSize<C>: ModulusSize,
    CompressedPoint<C>: Copy,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C> PrimeCurve for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    FieldBytes<C>: Copy,
    FieldBytesSize<C>: ModulusSize,
    CompressedPoint<C>: Copy,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
    type Affine = AffinePoint<C>;
}

impl<C> PartialEq for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C> ToEncodedPoint<C> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
    FieldBytesSize<C>: ModulusSize,
    CompressedPoint<C>: Copy,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C> {
        self.to_affine().to_encoded_point(compress)
    }
}

impl<C> TryFrom<ProjectivePoint<C>> for PublicKey<C>
where
    C: PrimeCurveParams,
{
    type Error = Error;

    fn try_from(point: ProjectivePoint<C>) -> Result<PublicKey<C>> {
        AffinePoint::<C>::from(point).try_into()
    }
}

impl<C> TryFrom<&ProjectivePoint<C>> for PublicKey<C>
where
    C: PrimeCurveParams,
{
    type Error = Error;

    fn try_from(point: &ProjectivePoint<C>) -> Result<PublicKey<C>> {
        AffinePoint::<C>::from(point).try_into()
    }
}

//
// Arithmetic trait impls
//

impl<C> Add<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add(&self, &other)
    }
}

impl<C> Add<&ProjectivePoint<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add(self, other)
    }
}

impl<C> Add<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add(&self, other)
    }
}

impl<C> AddAssign<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn add_assign(&mut self, rhs: ProjectivePoint<C>) {
        *self = ProjectivePoint::add(self, &rhs);
    }
}

impl<C> AddAssign<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn add_assign(&mut self, rhs: &ProjectivePoint<C>) {
        *self = ProjectivePoint::add(self, rhs);
    }
}

impl<C> Add<AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add_mixed(&self, &other)
    }
}

impl<C> Add<&AffinePoint<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add_mixed(self, other)
    }
}

impl<C> Add<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add_mixed(&self, other)
    }
}

impl<C> AddAssign<AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn add_assign(&mut self, rhs: AffinePoint<C>) {
        *self = ProjectivePoint::add_mixed(self, &rhs);
    }
}

impl<C> AddAssign<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn add_assign(&mut self, rhs: &AffinePoint<C>) {
        *self = ProjectivePoint::add_mixed(self, rhs);
    }
}

impl<C> Sum for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(ProjectivePoint::IDENTITY, |a, b| a + b)
    }
}

impl<'a, C> Sum<&'a ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sum<I: Iterator<Item = &'a ProjectivePoint<C>>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl<C> Sub<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub(&self, &other)
    }
}

impl<C> Sub<&ProjectivePoint<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub(self, other)
    }
}

impl<C> Sub<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub(&self, other)
    }
}

impl<C> SubAssign<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sub_assign(&mut self, rhs: ProjectivePoint<C>) {
        *self = ProjectivePoint::sub(self, &rhs);
    }
}

impl<C> SubAssign<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sub_assign(&mut self, rhs: &ProjectivePoint<C>) {
        *self = ProjectivePoint::sub(self, rhs);
    }
}

impl<C> Sub<AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub_mixed(&self, &other)
    }
}

impl<C> Sub<&AffinePoint<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub_mixed(self, other)
    }
}

impl<C> Sub<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub_mixed(&self, other)
    }
}

impl<C> SubAssign<AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sub_assign(&mut self, rhs: AffinePoint<C>) {
        *self = ProjectivePoint::sub_mixed(self, &rhs);
    }
}

impl<C> SubAssign<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sub_assign(&mut self, rhs: &AffinePoint<C>) {
        *self = ProjectivePoint::sub_mixed(self, rhs);
    }
}

impl<C, S> Mul<S> for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    S: Borrow<Scalar<C>>,
{
    type Output = Self;

    fn mul(self, scalar: S) -> Self {
        ProjectivePoint::mul(&self, scalar.borrow())
    }
}

impl<C> Mul<&Scalar<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
    ProjectivePoint<C>: Double,
{
    type Output = ProjectivePoint<C>;

    fn mul(self, scalar: &Scalar<C>) -> ProjectivePoint<C> {
        ProjectivePoint::mul(self, scalar)
    }
}

impl<C, S> MulAssign<S> for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    S: Borrow<Scalar<C>>,
{
    fn mul_assign(&mut self, scalar: S) {
        *self = ProjectivePoint::mul(self, scalar.borrow());
    }
}

impl<C> Neg for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn neg(self) -> ProjectivePoint<C> {
        ProjectivePoint::neg(&self)
    }
}

impl<'a, C> Neg for &'a ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn neg(self) -> ProjectivePoint<C> {
        ProjectivePoint::neg(self)
    }
}
