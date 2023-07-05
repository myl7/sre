// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

//! See [`MF`]

use std::marker::PhantomData;

use hmac::{Hmac, Mac};
use rand::prelude::*;
use sha2::Sha256;

/// `MF`. API of multi-puncturable PRF.
/// Refers to `t`-Punc-PRF with an addtional property.
/// `$t(\cdot)$` is a fixed polynomial.
///
/// - Generic parameter `K` is for the PRF key.
/// - Generic parameter `PK` is for the punctured key.
/// - Generic parameter `Y` is for `$\mathcol{Y}$`.
/// - `$\mathcol{X}$` is `$[N]$` where `N` is the provided generic parameter.
pub trait MF<const N: usize, K, PK, Y> {
    /// `MF.Setup`.
    ///
    /// Returns a description (i.e., the structure or representation) of a PRF key.
    fn setup<R>(rng: &mut R) -> K
    where
        R: Rng + ?Sized;
    /// `MF.Punc`.
    ///
    /// - `k` is the PRF key.
    /// - `ss` is a set of elements `S` s.t. `$|S| \le t(\lambda)$`.
    ///
    /// Returns a punctured key.
    fn punc(k: &K, ss: &[usize]) -> PK;
    /// `MF.Eval`.
    ///
    /// - `ks` is the punctured key.
    /// - `x` is the evaluated point. `$x \in [2^LOGN]$`.
    ///
    /// Returns `Y` if `$x \notin S$` otherwise `None`.
    fn eval(ks: &PK, x: usize) -> Option<Y>;
}

/// GGM tree-based PRF as multi-puncturable PRF implementation.
pub struct GGMPuncPRF<const LAMBDA: usize, const N: usize, KD>
where
    KD: GGMKeyDerive<LAMBDA>,
{
    _phantom: PhantomData<KD>,
}

pub struct GGMPRFKey<const LAMBDA: usize> {
    pub init_key: [u8; LAMBDA],
}

pub struct GGMPuncKey<const LAMBDA: usize> {
    pub nodes: Vec<GGMNode<LAMBDA>>,
    pub init_level: u32,
}

impl<const LAMBDA: usize, const N: usize, KD>
    MF<N, GGMPRFKey<LAMBDA>, GGMPuncKey<LAMBDA>, [u8; LAMBDA]> for GGMPuncPRF<LAMBDA, N, KD>
where
    KD: GGMKeyDerive<LAMBDA>,
{
    fn setup<R>(rng: &mut R) -> GGMPRFKey<LAMBDA>
    where
        R: Rng + ?Sized,
    {
        let mut init_key = [0; LAMBDA];
        rng.fill_bytes(&mut init_key);
        GGMPRFKey { init_key }
    }

    fn punc(k: &GGMPRFKey<LAMBDA>, ss: &[usize]) -> GGMPuncKey<LAMBDA> {
        let init_level = (N as f64).log2().ceil() as u32;
        let left_nodes: Vec<_> = (0..N)
            .filter(|i| !ss.contains(i))
            .map(|i| GGMNode4MinCov {
                i,
                level: init_level,
            })
            .collect();
        let nodes: Vec<_> = ggm_min_cover(left_nodes)
            .into_iter()
            .map(|GGMNode4MinCov { i, level }| {
                let mut node = GGMNode {
                    i,
                    key: k.init_key,
                    level,
                };
                ggm_key_derive_helper::<LAMBDA, KD>(&mut node.key, i, level, 0);
                node
            })
            .collect();
        GGMPuncKey { nodes, init_level }
    }

    fn eval(ks: &GGMPuncKey<LAMBDA>, x: usize) -> Option<[u8; LAMBDA]> {
        // `ks.nodes` covers the whole left tree without overlapping.
        // `x` can find the node covering it by comparing its prefix.
        ks.nodes.iter().find_map(|node| {
            if x >> (ks.init_level - node.level) == node.i {
                let mut derived_key = node.key;
                ggm_key_derive_helper::<LAMBDA, KD>(
                    &mut derived_key,
                    x,
                    ks.init_level - node.level,
                    0,
                );
                Some(derived_key)
            } else {
                None
            }
        })
    }
}

/// For minimum coverage.
/// See [`GGMNode`] for fields.
#[derive(Clone, Copy)]
struct GGMNode4MinCov {
    pub i: usize,
    pub level: u32,
}

pub struct GGMNode<const LAMBDA: usize> {
    /// `$i \in [N]$`
    pub i: usize,
    pub key: [u8; LAMBDA],
    /// `$level \in [\left \lceil{\log{N}}\right \rceil]$`
    pub level: u32,
}

/// Find minimum coverage of GGM tree, which is stored in a vector
fn ggm_min_cover(nodes: Vec<GGMNode4MinCov>) -> Vec<GGMNode4MinCov> {
    let mut next_level_nodes = vec![];
    let mut i = 0;
    while i < nodes.len() {
        if i + 1 == nodes.len() {
            next_level_nodes.push(nodes[i]);
            break;
        }
        if nodes[i].i >> 1 == nodes[i + 1].i >> 1 && nodes[i].level == nodes[i + 1].level {
            next_level_nodes.push(GGMNode4MinCov {
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

fn ggm_key_derive_helper<const LAMBDA: usize, KD>(
    key: &mut [u8; LAMBDA],
    i: usize,
    level: u32,
    dest_level: u32,
) where
    KD: GGMKeyDerive<LAMBDA>,
{
    if level <= dest_level {
        return;
    }
    for k in (dest_level + 1..level + 1).rev() {
        let k_bit = ((i & (1 << (k - 1))) >> (k - 1)) as u8;
        KD::key_derive(key, &[k_bit]);
    }
}

pub trait GGMKeyDerive<const LAMBDA: usize> {
    fn key_derive(key: &mut [u8; LAMBDA], input: &[u8]);
}

pub struct HmacSha256GGMKeyDerive;

impl GGMKeyDerive<32> for HmacSha256GGMKeyDerive {
    fn key_derive(key: &mut [u8; 32], input: &[u8]) {
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
        let prf_key = GGMPuncPRF::<32, N, HmacSha256GGMKeyDerive>::setup(&mut thread_rng());
        let punc_key = GGMPuncPRF::<32, N, HmacSha256GGMKeyDerive>::punc(&prf_key, PUNC_POINTS);
        for x in 0..N {
            let y = GGMPuncPRF::<32, N, HmacSha256GGMKeyDerive>::eval(&punc_key, x);
            if PUNC_POINTS.contains(&x) {
                assert!(y.is_none());
            } else {
                assert!(y.is_some());
            }
        }
    }

    #[test]
    fn test_ggm_punc_y_unchanged() {
        let prf_key = GGMPuncPRF::<32, N, HmacSha256GGMKeyDerive>::setup(&mut thread_rng());
        let punc_key0 = GGMPuncPRF::<32, N, HmacSha256GGMKeyDerive>::punc(&prf_key, &[]);
        let ys0: Vec<_> = (0..N)
            .into_iter()
            .map(|x| GGMPuncPRF::<32, N, HmacSha256GGMKeyDerive>::eval(&punc_key0, x))
            .collect();
        let punc_key1 = GGMPuncPRF::<32, N, HmacSha256GGMKeyDerive>::punc(&prf_key, PUNC_POINTS);
        let ys1: Vec<_> = (0..N)
            .into_iter()
            .map(|x| GGMPuncPRF::<32, N, HmacSha256GGMKeyDerive>::eval(&punc_key1, x))
            .collect();
        for (y0, y1) in ys0.iter().zip(ys1.iter()) {
            match (y0, y1) {
                (Some(y0_val), Some(y1_val)) => assert_eq!(y0_val, y1_val),
                _ => (),
            }
        }
    }
}
