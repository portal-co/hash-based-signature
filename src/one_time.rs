use core::{array, marker::PhantomData};

use digest::{
    generic_array::{self, functional::FunctionalSequence, ArrayLength, GenericArray},
    Digest,
};
use signature::{Signer, SignerMut};
// pub struct HashOneTimeNullSK<D: Digest>(pub generic_array::GenericArray<u8, D::OutputSize>);
// pub struct HashOneTimeNullVK<D: Digest>(pub generic_array::GenericArray<u8, D::OutputSize>);

// impl<D: Digest> HashOneTimeNullSK<D> {
//     pub fn sign(self) -> Self {
//         return self;
//     }
//     pub fn to_vk(&self) -> HashOneTimeNullVK<D> {
//         return HashOneTimeNullVK(D::digest(&self.0));
//     }
// }
// impl<D: Digest> HashOneTimeNullVK<D> {
//     pub fn verify(&self, sig: &HashOneTimeNullSK<D>) -> bool {
//         return self.0 == D::digest(&sig.0);
//     }
// }
// pub struct HashOneTimeOneBitSK<D: Digest> {
//     pub zero: HashOneTimeNullSK<D>,
//     pub one: HashOneTimeNullSK<D>,
// }
// pub struct HashOneTimeOneBitVK<D: Digest>(pub [HashOneTimeNullVK<D>; 2]);
// impl<D: Digest> HashOneTimeOneBitSK<D> {
//     pub fn sign(self, a: bool) -> HashOneTimeNullSK<D> {
//         if a {
//             self.zero.sign()
//         } else {
//             self.one.sign()
//         }
//     }
//     pub fn to_vk(&self) -> HashOneTimeOneBitVK<D> {
//         return HashOneTimeOneBitVK([self.zero.to_vk(), self.one.to_vk()]);
//     }
// }
// impl<D: Digest> HashOneTimeOneBitVK<D> {
//     pub fn verify(&self, a: bool, sig: &HashOneTimeNullSK<D>) -> bool {
//         return if a { &self.0[0] } else { &self.0[1] }.verify(sig);
//     }
// }
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashOneTimeByteSK<D: Digest>(pub [generic_array::GenericArray<u8, D::OutputSize>; 2]);
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashOneTimeByteVK<D: Digest>(pub [generic_array::GenericArray<u8, D::OutputSize>; 2]);
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashOneTimeByteSig<D: Digest>(pub [generic_array::GenericArray<u8, D::OutputSize>; 2]);
impl<D: Digest> HashOneTimeByteSK<D> {
    pub fn sign(self, mut a: u8) -> HashOneTimeByteSig<D> {
        let [v0, v1] = self.0;
        return HashOneTimeByteSig([
            (0..a).fold(v0, |a, _| D::digest(a)),
            (a..=255).fold(v1, |a, _| D::digest(a)),
        ]);
    }
    pub fn to_vk(&self) -> HashOneTimeByteVK<D> {
        return HashOneTimeByteVK(
            self.0
                .clone()
                .map(|v| (0..=255u8).fold(v, |a, _| D::digest(a))),
        );
    }
}
impl<D: Digest> HashOneTimeByteVK<D> {
    pub fn verify(&self, mut a: u8, sig: &HashOneTimeByteSig<D>) -> bool {
        return (a..=255).fold(sig.0[0].clone(), |a, _| D::digest(a)) == self.0[0]
            && (0..a).fold(sig.0[1].clone(), |a, _| D::digest(a)) == self.0[1];
    }
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct HashOneTimeSK<D: SigDigest>(
    #[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
    pub  generic_array::GenericArray<HashOneTimeByteSK<D>, D::OutputSize>,
);
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct HashOneTimeVK<D: SigDigest>(
    #[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
    pub  generic_array::GenericArray<HashOneTimeByteVK<D>, D::OutputSize>,
);
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct HashOneTimeSig<D: SigDigest>(
    #[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
    pub  generic_array::GenericArray<HashOneTimeByteSig<D>, D::OutputSize>,
);
pub trait SigDigest:
    Digest<
        OutputSize: ArrayLength<HashOneTimeByteSK<Self>>
                        + ArrayLength<HashOneTimeByteVK<Self>>
                        + ArrayLength<HashOneTimeByteSig<Self>>,
    > + Sized
    + Default
{
}
impl<
        D: Digest<
                OutputSize: ArrayLength<HashOneTimeByteSK<D>>
                                + ArrayLength<HashOneTimeByteVK<D>>
                                + ArrayLength<HashOneTimeByteSig<D>>,
            > + Default,
    > SigDigest for D
{
}
impl<D: SigDigest> HashOneTimeSK<D> {
    pub fn sign(self, a: &[u8]) -> HashOneTimeSig<D> {
        let a = D::digest(a);
        return HashOneTimeSig(a.zip(self.0, |a, b| b.sign(a)));
    }
    pub fn to_vk(&self) -> HashOneTimeVK<D> {
        return HashOneTimeVK(
            GenericArray::from_exact_iter(self.0.iter().map(|a| a.to_vk())).unwrap(),
        );
    }
}
impl<D: SigDigest> HashOneTimeVK<D> {
    pub fn verify(&self, a: &[u8], sig: &HashOneTimeSig<D>) -> bool {
        return D::digest(a)
            .into_iter()
            .zip(self.0.iter())
            .zip(sig.0.iter())
            .all(|((a, b), c)| b.verify(a, c));
    }
}
