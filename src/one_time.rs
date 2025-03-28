use core::{array, cmp::Ordering, marker::PhantomData};

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

macro_rules! otb_sk {
    ($t:ident) => {
        #[cfg(feature = "embedded-io")]
        const _: () = {
            use embedded_io::{ErrorType, Read, ReadExactError, Write};
            impl<D: Digest> $t<D> {
                pub fn read_sync<T: Read>(r: &mut T) -> Result<Self, ReadExactError<T::Error>> {
                    let (mut a, mut b) = <(
                        generic_array::GenericArray<_, _>,
                        generic_array::GenericArray<_, _>,
                    ) as Default>::default();
                    r.read_exact(&mut a)?;
                    r.read_exact(&mut b)?;
                    Ok(Self([a, b]))
                }
                pub fn write_sync<T: Write>(&self, t: &mut T) -> Result<(), T::Error> {
                    t.write_all(&self.0[0])?;
                    t.write_all(&self.0[1])?;
                    Ok(())
                }
            }
        };
        #[cfg(feature = "embedded-io-async")]
        const _: () = {
            use embedded_io_async::{ErrorType, Read, ReadExactError, Write};
            impl<D: Digest> $t<D> {
                pub async fn read_async<T: Read>(
                    r: &mut T,
                ) -> Result<Self, ReadExactError<T::Error>> {
                    let (mut a, mut b) = <(
                        generic_array::GenericArray<_, _>,
                        generic_array::GenericArray<_, _>,
                    ) as Default>::default();
                    r.read_exact(&mut a).await?;
                    r.read_exact(&mut b).await?;
                    Ok(Self([a, b]))
                }
                pub async fn write_async<T: Write>(&self, t: &mut T) -> Result<(), T::Error> {
                    t.write_all(&self.0[0]).await?;
                    t.write_all(&self.0[1]).await?;
                    Ok(())
                }
            }
        };
        impl<D: Digest> Default for $t<D> {
            fn default() -> Self {
                Self(Default::default())
            }
        }
        impl<D: Digest> Clone for $t<D> {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }
        impl<D: Digest> PartialEq for $t<D> {
            fn eq(&self, other: &Self) -> bool {
                return self.0 == other.0;
            }
        }
        impl<D: Digest> Eq for $t<D> {}
        impl<D: Digest> PartialOrd for $t<D> {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                self.0.partial_cmp(&other.0)
            }
        }
        impl<D: Digest> Ord for $t<D> {
            fn cmp(&self, other: &Self) -> Ordering {
                self.0.cmp(&other.0)
            }
        }
    };
}
// #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashOneTimeByteSK<D: Digest>(pub [generic_array::GenericArray<u8, D::OutputSize>; 2]);
otb_sk!(HashOneTimeByteSK);
// #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashOneTimeByteVK<D: Digest>(pub [generic_array::GenericArray<u8, D::OutputSize>; 2]);
otb_sk!(HashOneTimeByteVK);
// #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashOneTimeByteSig<D: Digest>(pub [generic_array::GenericArray<u8, D::OutputSize>; 2]);
otb_sk!(HashOneTimeByteSig);
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
macro_rules! ot_sk {
    ($t:ident => $u:ident) => {
        #[cfg(feature = "embedded-io")]
        const _: () = {
            use embedded_io::{ErrorType, Read, ReadExactError, Write};
            impl<D: SigDigest> $t<D> {
                pub fn read_sync<T: Read>(r: &mut T) -> Result<Self, ReadExactError<T::Error>> {
                    Ok(Self(
                        <generic_array::GenericArray<(), D::OutputSize> as Default>::default()
                            .into_iter()
                            .map(|_| $u::<D>::read_sync(r))
                            .collect::<Result<_, ReadExactError<T::Error>>>()?,
                    ))
                }
                pub fn write_sync<T: Write>(&self, t: &mut T) -> Result<(), T::Error> {
                    for s in self.0.iter() {
                        s.write_sync(t)?;
                    }
                    Ok(())
                }
            }
        };
        #[cfg(feature = "embedded-io-async")]
        const _: () = {
            use embedded_io_async::{ErrorType, Read, ReadExactError, Write};
            impl<D: SigDigest> $t<D> {
                pub async fn read_async<T: Read>(
                    rd: &mut T,
                ) -> Result<Self, ReadExactError<T::Error>> {
                    let mut r: generic_array::GenericArray<$u<D>, D::OutputSize> =
                        Default::default();
                    for r in r.iter_mut() {
                        *r = $u::<D>::read_async(rd).await?;
                    }
                    Ok(Self(r))
                }
                pub async fn write_async<T: Write>(&self, t: &mut T) -> Result<(), T::Error> {
                    for s in self.0.iter() {
                        s.write_async(t).await?;
                    }
                    Ok(())
                }
            }
        };
        impl<D: SigDigest> Default for $t<D> {
            fn default() -> Self {
                Self(Default::default())
            }
        }
        impl<D: SigDigest> Clone for $t<D> {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }
        impl<D: SigDigest> PartialEq for $t<D> {
            fn eq(&self, other: &Self) -> bool {
                return self.0 == other.0;
            }
        }
        impl<D: SigDigest> Eq for $t<D> {}
        impl<D: SigDigest> PartialOrd for $t<D> {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                self.0.partial_cmp(&other.0)
            }
        }
        impl<D: SigDigest> Ord for $t<D> {
            fn cmp(&self, other: &Self) -> Ordering {
                self.0.cmp(&other.0)
            }
        }
    };
}
// #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct HashOneTimeSK<D: SigDigest>(
    #[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
    pub  generic_array::GenericArray<HashOneTimeByteSK<D>, D::OutputSize>,
);
ot_sk!(HashOneTimeSK => HashOneTimeByteSK);
// #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct HashOneTimeVK<D: SigDigest>(
    #[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
    pub  generic_array::GenericArray<HashOneTimeByteVK<D>, D::OutputSize>,
);
ot_sk!(HashOneTimeVK => HashOneTimeByteVK);
// #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct HashOneTimeSig<D: SigDigest>(
    #[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
    pub  generic_array::GenericArray<HashOneTimeByteSig<D>, D::OutputSize>,
);
ot_sk!(HashOneTimeSig => HashOneTimeByteSig);
pub trait SigDigest:
    Digest<
        OutputSize: ArrayLength<HashOneTimeByteSK<Self>>
                        + ArrayLength<HashOneTimeByteVK<Self>>
                        + ArrayLength<HashOneTimeByteSig<Self>>
                        + ArrayLength<()>,
    > + Sized // + Default
{
}
impl<
        D: Digest<
            OutputSize: ArrayLength<HashOneTimeByteSK<D>>
                            + ArrayLength<HashOneTimeByteVK<D>>
                            + ArrayLength<HashOneTimeByteSig<D>>
                            + ArrayLength<()>,
        >,
    > SigDigest for D
{
}
impl<D: SigDigest> HashOneTimeSK<D> {
    pub fn sign(self, a: &[u8]) -> HashOneTimeSig<D> {
        let mut d = D::new();
        d.update(a);
        self.sign_live(d)
    }
    pub fn sign_live(self, a: D) -> HashOneTimeSig<D> {
        let a = a.finalize();
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
        let mut d = D::new();
        d.update(a);
        self.verify_live(d, sig)
    }
    pub fn verify_live(&self, a: D, sig: &HashOneTimeSig<D>) -> bool {
        return a
            .finalize()
            .into_iter()
            .zip(self.0.iter())
            .zip(sig.0.iter())
            .all(|((a, b), c)| b.verify(a, c));
    }
}
