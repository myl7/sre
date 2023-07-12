// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

//! See [`Bloom`]

use std::hash::Hasher;

use bitvec::prelude::*;
use siphasher::sip::SipHasher;

/// `BF`. API of `(b, h, n)`-Bloom filter.
///
/// - `n` is the maximum number of elements to be inserted.
/// - `b` is the number of Bloom filter entries.
/// - Number `h` is the number of hash functions.
///
/// - `B` is a `b`-bit array as the state.
///   Generic parameter `BN` is the **byte** len of `B`. So `b = BN * 8`.
/// - Generic parameter `HN = h`.
/// - Generic parameter `HS` is for hash function states. Refers to `H` in the paper.
pub trait Bloom<const BN: usize, const HN: usize, HS> {
    /// `BF.Gen`.
    ///
    /// Returns `h` hash functions and `B`.
    fn gen(&self) -> ([HS; HN], [u8; BN]);
    /// `BF.Upd`.
    ///
    /// - `hs` is all hash function instances.
    /// - `bs` is `B`. Modified in-place.
    /// - `x` is the input to be hashed.
    fn upd(&self, hs: &[HS; HN], bs: &mut [u8; BN], x: &[u8]);
    /// `BF.Check`
    ///
    /// - `hs` is all hash function instances.
    /// - `bs` is `B`.
    /// - `x` is the input to be hashed.
    fn check(&self, hs: &[HS; HN], bs: &[u8; BN], x: &[u8]) -> bool;
}

/// Bloom filter implementation.
///
/// `H` is seeded like [shangqimonash/Aura:BF/BloomFilter.h].
///
/// [shangqimonash/Aura:BF/BloomFilter.h]: https://github.com/shangqimonash/Aura/blob/master/BF/BloomFilter.h
pub struct BloomImpl<const BN: usize, const HN: usize, H>
where
    H: BloomH<BN>,
{
    h: H,
}

impl<const BN: usize, const HN: usize, H> BloomImpl<BN, HN, H>
where
    H: BloomH<BN>,
{
    pub fn new(h: H) -> Self {
        Self { h }
    }

    pub fn h(&self) -> &H {
        &self.h
    }
}

impl<const BN: usize, const HN: usize, H> Bloom<BN, HN, usize> for BloomImpl<BN, HN, H>
where
    H: BloomH<BN>,
{
    fn gen(&self) -> ([usize; HN], [u8; BN]) {
        (std::array::from_fn(|i| i), [0; BN])
    }

    fn upd(&self, hs: &[usize; HN], bs: &mut [u8; BN], x: &[u8]) {
        hs.iter().for_each(|&i| {
            let index = self.h.hash(x, i) % BN;
            bs.view_bits_mut::<Lsb0>().set(index, true);
        })
    }

    fn check(&self, hs: &[usize; HN], bs: &[u8; BN], x: &[u8]) -> bool {
        hs.iter().all(|&i| {
            let index = self.h.hash(x, i) % BN;
            bs.view_bits::<Lsb0>()[index]
        })
    }
}

/// API of hash function for the above Bloom filter implementation.
///
/// `$\rightarrow [b]$`. See [`Bloom`] for `b`.
pub trait BloomH<const BN: usize> {
    /// Keyed hashing.
    ///
    /// - `x` is the input to be hashed.
    /// - `i` is the index of the hash function as the seed.
    fn hash(&self, x: &[u8], i: usize) -> usize;
}

/// SipHash 2-4 as hash function implementation
#[derive(Default)]
pub struct SipH<const BN: usize>;

impl<const BN: usize> SipH<BN> {
    pub fn new() -> Self {
        Self
    }
}

impl<const BN: usize> BloomH<BN> for SipH<BN> {
    /// Returns `u64` actually.
    ///
    /// `usize` involved should be `u64`.
    fn hash(&self, x: &[u8], i: usize) -> usize {
        let mut hasher = SipHasher::new_with_keys(i as u64, 0);
        hasher.write(x);
        hasher.finish() as usize % (BN * 8)
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
        let h_impl = SipH::<BN>::new();
        let bf = BloomImpl::<BN, HN, _>::new(h_impl);
        let (hs, mut bs) = bf.gen();
        XS.iter().for_each(|&x| {
            bf.upd(&hs, &mut bs, x);
        });
        XS.iter().for_each(|&x| {
            assert!(bf.check(&hs, &bs, x));
        });
    }

    #[test]
    fn test_siph_upd_then_check_not_false_positive() {
        let h_impl = SipH::<BN>::new();
        let bf = BloomImpl::<BN, HN, _>::new(h_impl);
        let (hs, mut bs) = bf.gen();
        XS.iter().for_each(|&x| {
            bf.upd(&hs, &mut bs, x);
        });
        let x = b"\xb2_!\\\xdf\x1b\xac\xdc\xd0\xfa} \xad\x11\x8e\xeb";
        assert_eq!(bf.check(&hs, &bs, x), false);
    }
}
