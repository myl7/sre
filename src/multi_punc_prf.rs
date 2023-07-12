// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

//! See [`MultiPuncPrf`]

use hmac::{Hmac, Mac};
use rand::prelude::*;
use sha2::Sha256;

/// `MF`. API of multi-puncturable PRF.
/// Refers to `t`-Punc-PRF with an addtional property.
/// `$t(\cdot)$` is a fixed polynomial.
///
/// - Generic parameter `K` is for the PRF key.
/// - Generic parameter `Pk` is for the punctured key.
/// - Generic parameter `Y` is for `$\mathcol{Y}$`.
/// - `$\mathcol{X}$` is `$[N]$` where `N` is the provided generic parameter.
pub trait MultiPuncPrf<const N: usize, K, Pk, Y> {
    /// `MF.Setup`.
    ///
    /// Returns a description (i.e., the structure or representation) of a PRF key.
    fn setup<R>(&self, rng: &mut R) -> K
    where
        R: Rng + ?Sized;
    /// `MF.Punc`.
    ///
    /// - `k` is the PRF key.
    /// - `ss` is a set of elements `S` s.t. `$|S| \le t(\lambda)$`.
    ///
    /// Returns a punctured key.
    fn punc(&self, k: &K, ss: &[usize]) -> Pk;
    /// `MF.Eval`.
    ///
    /// - `ks` is the punctured key.
    /// - `x` is the evaluated point. `$x \in [2^LOGN]$`.
    ///
    /// Returns `Y` if `$x \notin S$` otherwise `None`.
    fn eval(&self, ks: &Pk, x: usize) -> Option<Y>;
    /// `F`.
    ///
    /// It works like `kp = punc(k, [])` then `eval(kp, x)`, which is the default implementation.
    /// Provided for possible optimization.
    /// Or say this is the actual start point.
    fn f(&self, k: &K, x: usize) -> Option<Y> {
        let kp = self.punc(k, &[]);
        self.eval(&kp, x)
    }
}

/// GGM tree-based PRF as multi-puncturable PRF implementation.
pub struct GgmMultiPuncPrf<const LAMBDA: usize, const N: usize, KD>
where
    KD: GgmKeyDerive<LAMBDA>,
{
    kd: KD,
}

impl<const LAMBDA: usize, const N: usize, KD> GgmMultiPuncPrf<LAMBDA, N, KD>
where
    KD: GgmKeyDerive<LAMBDA>,
{
    pub fn new(kd: KD) -> Self {
        Self { kd }
    }
}

pub struct GgmPrfKey<const LAMBDA: usize> {
    pub init_key: [u8; LAMBDA],
}

pub struct GgmPuncKey<const LAMBDA: usize> {
    pub nodes: Vec<GgmNode<LAMBDA>>,
    pub init_level: u32,
}

impl<const LAMBDA: usize, const N: usize, KD>
    MultiPuncPrf<N, GgmPrfKey<LAMBDA>, GgmPuncKey<LAMBDA>, [u8; LAMBDA]>
    for GgmMultiPuncPrf<LAMBDA, N, KD>
where
    KD: GgmKeyDerive<LAMBDA>,
{
    fn setup<R>(&self, rng: &mut R) -> GgmPrfKey<LAMBDA>
    where
        R: Rng + ?Sized,
    {
        let mut init_key = [0; LAMBDA];
        rng.fill_bytes(&mut init_key);
        GgmPrfKey { init_key }
    }

    fn punc(&self, k: &GgmPrfKey<LAMBDA>, ss: &[usize]) -> GgmPuncKey<LAMBDA> {
        let init_level = (N as f64).log2().ceil() as u32;
        let left_nodes: Vec<_> = (0..N)
            .filter(|i| !ss.contains(i))
            .map(|i| GgmNodeForMinCov {
                i,
                level: init_level,
            })
            .collect();
        let nodes: Vec<_> = ggm_min_cover(left_nodes)
            .into_iter()
            .map(|GgmNodeForMinCov { i, level }| {
                let mut node = GgmNode {
                    i,
                    key: k.init_key,
                    level,
                };
                ggm_key_derive_helper(&self.kd, &mut node.key, i, level, 0);
                node
            })
            .collect();
        GgmPuncKey { nodes, init_level }
    }

    /// `ks.nodes` covers the whole left tree without overlapping.
    /// `x` can find the node covering it by comparing its prefix.
    fn eval(&self, ks: &GgmPuncKey<LAMBDA>, x: usize) -> Option<[u8; LAMBDA]> {
        ks.nodes.iter().find_map(|node| {
            if x >> (ks.init_level - node.level) == node.i {
                let mut derived_key = node.key;
                ggm_key_derive_helper(&self.kd, &mut derived_key, x, ks.init_level - node.level, 0);
                Some(derived_key)
            } else {
                None
            }
        })
    }

    /// No need to compute the minimum coverage.
    /// Just use the binary form of `x` to derive the key.
    fn f(&self, k: &GgmPrfKey<LAMBDA>, x: usize) -> Option<[u8; LAMBDA]> {
        if x >= N {
            return None;
        }
        let init_level = (N as f64).log2().ceil() as u32;
        let mut derived_key = k.init_key;
        ggm_key_derive_helper::<LAMBDA, KD>(&self.kd, &mut derived_key, x, init_level, 0);
        Some(derived_key)
    }
}

/// For minimum coverage.
/// See [`GgmNode`] for fields.
#[derive(Clone, Copy)]
struct GgmNodeForMinCov {
    pub i: usize,
    pub level: u32,
}

pub struct GgmNode<const LAMBDA: usize> {
    /// `$i \in [N]$`
    pub i: usize,
    pub key: [u8; LAMBDA],
    /// `$level \in [\left \lceil{\log{N}}\right \rceil]$`
    pub level: u32,
}

/// Find minimum coverage of GGM tree, which is stored in a vector.
///
/// `i` of the node representing the position in the binary tree is in the MSB form,
/// which means for `0b1010`, the topest branch is `1`.
fn ggm_min_cover(nodes: Vec<GgmNodeForMinCov>) -> Vec<GgmNodeForMinCov> {
    let mut next_level_nodes = vec![];
    let mut i = 0;
    while i < nodes.len() {
        if i + 1 == nodes.len() {
            next_level_nodes.push(nodes[i]);
            break;
        }
        if nodes[i].i >> 1 == nodes[i + 1].i >> 1 && nodes[i].level == nodes[i + 1].level {
            next_level_nodes.push(GgmNodeForMinCov {
                i: nodes[i].i >> 1,
                level: nodes[i].level - 1,
            });
            i += 1;
        } else {
            next_level_nodes.push(nodes[i]);
        }
        i += 1;
    }
    if next_level_nodes.len() == nodes.len() || next_level_nodes.is_empty() {
        return nodes;
    }
    ggm_min_cover(next_level_nodes)
}

/// Bit-by-bit rotation to ensure when `a = b || c`, `derive(k, a) = derive(derive(k, b), c)`.
///
/// Maybe there is a faster way, but this is from [shangqimonash/Aura](https://github.com/shangqimonash/Aura) .
fn ggm_key_derive_helper<const LAMBDA: usize, KD>(
    kd: &KD,
    key: &mut [u8; LAMBDA],
    i: usize,
    level: u32,
    dest_level: u32,
) where
    KD: GgmKeyDerive<LAMBDA>,
{
    if level <= dest_level {
        return;
    }
    for k in (dest_level + 1..level + 1).rev() {
        let k_bit = ((i & (1 << (k - 1))) >> (k - 1)) as u8;
        kd.key_derive(key, &[k_bit]);
    }
}

pub trait GgmKeyDerive<const LAMBDA: usize> {
    fn key_derive(&self, key: &mut [u8; LAMBDA], input: &[u8]);
}

#[derive(Default)]
pub struct HmacSha256GgmKeyDerive;

impl HmacSha256GgmKeyDerive {
    pub fn new() -> Self {
        Self
    }
}

impl GgmKeyDerive<32> for HmacSha256GgmKeyDerive {
    fn key_derive(&self, key: &mut [u8; 32], input: &[u8]) {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(input);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();
        key.copy_from_slice(&code_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::thread_rng;

    const N: usize = 2usize.pow(4);
    const PUNC_POINTS: &[usize] = &[2, 7, 11];

    #[test]
    fn test_ggm_punc_then_eval_ok() {
        let kd = HmacSha256GgmKeyDerive::new();
        let mf = GgmMultiPuncPrf::<32, N, _>::new(kd);
        let prf_key = mf.setup(&mut thread_rng());
        let punc_key = mf.punc(&prf_key, PUNC_POINTS);
        for x in 0..N {
            let y = mf.eval(&punc_key, x);
            if PUNC_POINTS.contains(&x) {
                assert!(y.is_none());
            } else {
                assert!(y.is_some());
            }
        }
    }

    #[test]
    fn test_ggm_punc_y_unchanged() {
        let kd = HmacSha256GgmKeyDerive::new();
        let mf = GgmMultiPuncPrf::<32, N, _>::new(kd);
        let prf_key = mf.setup(&mut thread_rng());
        let punc_key0 = mf.punc(&prf_key, &[]);
        let ys0: Vec<_> = (0..N).into_iter().map(|x| mf.eval(&punc_key0, x)).collect();
        let punc_key1 = mf.punc(&prf_key, PUNC_POINTS);
        let ys1: Vec<_> = (0..N).into_iter().map(|x| mf.eval(&punc_key1, x)).collect();
        for (y0, y1) in ys0.iter().zip(ys1.iter()) {
            match (y0, y1) {
                (Some(y0_val), Some(y1_val)) => assert_eq!(y0_val, y1_val),
                _ => (),
            }
        }
    }
}
