// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

//! See [`BF`]

use std::hash::Hasher;
use std::marker::PhantomData;

use bitvec::prelude::*;
use siphasher::sip::SipHasher;

/// `BF`. API of `(b, h, n)`-Bloom filter.
///
/// - `n` is the maximum number of elements to be inserted.
/// - `b` is the number of Bloom filter entries.
/// - `h` is the number of hash functions.
///
/// - `B` is a `b`-bit array as the state.
///   Generic parameter `BN` is the **byte** len of `B`. So `b = BN * 8`.
/// - Generic parameter `HN = h`.
/// - Generic parameter `HS` is for hash function states. Refers to `H` in the paper.
pub trait BF<const BN: usize, const HN: usize, HS> {
    /// `BF.Gen`.
    ///
    /// Returns `h` hash functions and `B`.
    fn gen() -> ([HS; HN], [u8; BN]);
    /// `BF.Upd`.
    ///
    /// - `hs` is all hash functions.
    /// - `bs` is `B`. Modified in-place.
    /// - `x` is the input to be hashed.
    fn upd(hs: &[HS; HN], bs: &mut [u8; BN], x: &[u8]);
    /// `BF.Check`
    ///
    /// - `hs` is all hash functions.
    /// - `bs` is `B`.
    /// - `x` is the input to be hashed.
    fn check(hs: &[HS; HN], bs: &[u8; BN], x: &[u8]) -> bool;
}

/// Bloom filter implementation.
///
/// `H` is seeded like [shangqimonash/Aura:BF/BloomFilter.h](https://github.com/shangqimonash/Aura/blob/master/BF/BloomFilter.h) .
pub struct BFImpl<const BN: usize, const HN: usize, H>
where
    H: BFImplH<BN>,
{
    _phantom: PhantomData<H>,
}

impl<const BN: usize, const HN: usize, H> BF<BN, HN, usize> for BFImpl<BN, HN, H>
where
    H: BFImplH<BN>,
{
    fn gen() -> ([usize; HN], [u8; BN]) {
        (std::array::from_fn(|i| i), [0; BN])
    }

    fn upd(hs: &[usize; HN], bs: &mut [u8; BN], x: &[u8]) {
        hs.iter().for_each(|&i| {
            let index = H::h(x, i) % BN;
            bs.view_bits_mut::<Lsb0>().set(index, true);
        })
    }

    fn check(hs: &[usize; HN], bs: &[u8; BN], x: &[u8]) -> bool {
        hs.iter().all(|&i| {
            let index = H::h(x, i) % BN;
            bs.view_bits::<Lsb0>()[index]
        })
    }
}

/// API of hash function for the above Bloom filter implementation.
///
/// `$\rightarrow [b]$`. See [`BF`] for `b`.
pub trait BFImplH<const BN: usize> {
    /// Keyed hashing.
    ///
    /// - `x` is the input to be hashed.
    /// - `i` is the index of the hash function as the seed.
    fn h(x: &[u8], i: usize) -> usize;
}

/// SipHash 2-4 as hash function implementation
pub struct SipH<const BN: usize> {
    pub i: u64,
}

impl<const BN: usize> BFImplH<BN> for SipH<BN> {
    /// Returns `u64` actually.
    ///
    /// `usize` involved should be `u64`.
    fn h(x: &[u8], i: usize) -> usize {
        let mut hasher = SipHasher::new_with_keys(i as u64, 0);
        hasher.write(&x);
        hasher.finish() as usize % ((BN * 8) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BN: usize = 8192;
    const HN: usize = 3;

    const XS: &[&[u8]] = &[
        b".S\x1c\x8f\xb1\x17\x92@\xd8e\xe0\xf0\xafe\x15x",
        b"\x80\xed\xba\x08\xa2<[\x82\xf2[w\xac\xa8\x14\xdb\xa9",
        b"\x15Z\x8a\x88L\xd4\x87\x91\xb9m)@\xcb\x94\x07\xcc",
    ];

    #[test]
    fn test_siph_upd_then_check_ok() {
        let (hs, mut bs) = BFImpl::<BN, HN, SipH<BN>>::gen();
        XS.iter().for_each(|&x| {
            BFImpl::<BN, HN, SipH<BN>>::upd(&hs, &mut bs, x);
        });
        XS.iter().for_each(|&x| {
            assert!(BFImpl::<BN, HN, SipH<BN>>::check(&hs, &bs, x));
        });
    }

    #[test]
    fn test_siph_upd_then_check_not_false_positive() {
        let (hs, mut bs) = BFImpl::<BN, HN, SipH<BN>>::gen();
        XS.iter().for_each(|&x| {
            BFImpl::<BN, HN, SipH<BN>>::upd(&hs, &mut bs, x);
        });
        let x = b"\xb2_!\\\xdf\x1b\xac\xdc\xd0\xfa} \xad\x11\x8e\xeb";
        assert_eq!(BFImpl::<BN, HN, SipH<BN>>::check(&hs, &bs, x), false);
    }
}
