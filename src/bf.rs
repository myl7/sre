// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

/// `BF`. API of `(b, h, n)`-Bloom filter.
/// `n` is the maximum number of elements to be inserted.
/// `b` is the number of Bloom filter entries.
/// `h` is the number of hash functions.
/// `B` is a `b`-bit array as the state.
/// Generic parameter `BN` is the **byte** len of `B`. So `b = BN * 8`.
/// Generic parameter `HN = h`.
pub trait BF<const LAMBDA: usize, const BN: usize, const HN: usize, HImpl>
where
    HImpl: H<LAMBDA>,
{
    /// `BF.Gen`.
    /// Returns `h` hash functions and `B`.
    fn gen() -> ([HImpl; HN], [u8; BN]);
    /// `BF.Upd`.
    /// `h_func` is a hash function.
    /// `b_state` is `B`. Modified in-place.
    /// `x` is the input to be hashed.
    fn upd(h_func: &HImpl, b_state: &mut [u8; BN], x: &[u8; LAMBDA]);
    /// `BF.Check`
    /// `h_func` is a hash function.
    /// `b_state` is `B`.
    fn check(h_func: &HImpl, b_state: &[u8; BN], x: &[u8; LAMBDA]) -> bool;
}

/// `H`. API of hash function.
/// $\rightarrow [b]$.
/// See [`BF`] for `b`.
pub trait H<const LAMBDA: usize> {}
