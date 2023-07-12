// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

//! See [`Sre`]

pub mod bloom;
pub mod multi_punc_prf;
pub mod symm_enc;

use bitvec::prelude::*;
use rand::prelude::*;

use crate::bloom::{Bloom, BloomH, BloomImpl};
use crate::multi_punc_prf::{GgmKeyDerive, GgmMultiPuncPrf, GgmPrfKey, GgmPuncKey, MultiPuncPrf};
use crate::symm_enc::SymmEnc;

/// `SRE`. API of symmetric revocable encryption.
///
/// See [`bf::Bloom`] for `BN` and `HN`.
pub trait Sre<const LAMBDA: usize, const HN: usize, MSK, SKR> {
    /// `SRE.KGen`
    fn kgen<R>(rng: &mut R) -> MSK
    where
        R: Rng + ?Sized;
    /// `SRE.Enc`.
    fn enc(msk: &MSK, m: &[u8], t: &[u8]) -> [Vec<u8>; HN];
    /// `SRE.KRev`
    fn krev(msk: &MSK, r: &[&[u8]]) -> SKR;
    /// `SRE.Dec`
    fn dec(skr: &SKR, ct: [&[u8]; HN], t: &[u8]) -> Option<Vec<u8>>;
}

/// Symmetric revocable encryption implementation.
///
/// To avoid `#![feature(generic_const_exprs)]`, it is **your responsibility** to ensure `N = BN * 8`.
pub struct SreImpl<const LAMBDA: usize, const BN: usize, const N: usize, const HN: usize, H, KD, SE>
where
    H: BloomH<BN>,
    KD: GgmKeyDerive<LAMBDA>,
    SE: SymmEnc<LAMBDA>,
{
    // TODO: Instantiation
    #[allow(dead_code)]
    h: H,
    // TODO: Instantiation
    #[allow(dead_code)]
    kd: KD,
    // TODO: Instantiation
    #[allow(dead_code)]
    se: SE,
}

/// `msk`. Secret key of symmetric revocable encryption.
pub struct MskImpl<const LAMBDA: usize, const BN: usize, const HN: usize> {
    pub sk: GgmPrfKey<LAMBDA>,
    pub hs: [usize; HN],
    pub bs: [u8; BN],
}

/// `$sk_R$`
pub struct SkrImpl<const LAMBDA: usize, const BN: usize, const HN: usize, HS> {
    pub ski: GgmPuncKey<LAMBDA>,
    pub hs: [HS; HN],
    pub bs: [u8; BN],
}

impl<const LAMBDA: usize, const BN: usize, const N: usize, const HN: usize, H, KD, SE>
    Sre<LAMBDA, HN, MskImpl<LAMBDA, BN, HN>, SkrImpl<LAMBDA, BN, HN, usize>>
    for SreImpl<LAMBDA, BN, N, HN, H, KD, SE>
where
    H: BloomH<BN>,
    KD: GgmKeyDerive<LAMBDA>,
    SE: SymmEnc<LAMBDA>,
{
    fn kgen<R>(rng: &mut R) -> MskImpl<LAMBDA, BN, HN>
    where
        R: Rng + ?Sized,
    {
        let (hs, bs) = BloomImpl::<BN, HN, H>::gen();
        let sk = GgmMultiPuncPrf::<LAMBDA, N, KD>::setup(rng);
        MskImpl::<LAMBDA, BN, HN> { sk, hs, bs }
    }

    fn enc(msk: &MskImpl<LAMBDA, BN, HN>, m: &[u8], t: &[u8]) -> [Vec<u8>; HN] {
        (0..HN)
            .map(|j| H::h(t, msk.hs[j]))
            .map(|i| GgmMultiPuncPrf::<LAMBDA, N, KD>::f(&msk.sk, i).unwrap())
            .map(|sk| SE::enc(&sk, m))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn krev(msk: &MskImpl<LAMBDA, BN, HN>, r: &[&[u8]]) -> SkrImpl<LAMBDA, BN, HN, usize> {
        assert!(r.len() <= N);
        let mut bs_buf = msk.bs.to_owned();
        r.iter()
            .for_each(|t| BloomImpl::<BN, HN, H>::upd(&msk.hs, &mut bs_buf, t));
        let is: Vec<_> = bs_buf.view_bits::<Lsb0>().iter_ones().collect();
        let punc_key = GgmMultiPuncPrf::<LAMBDA, N, KD>::punc(&msk.sk, &is);
        SkrImpl {
            ski: punc_key,
            hs: msk.hs.to_owned(),
            bs: bs_buf,
        }
    }

    fn dec(skr: &SkrImpl<LAMBDA, BN, HN, usize>, ct: [&[u8]; HN], t: &[u8]) -> Option<Vec<u8>> {
        if BloomImpl::<BN, HN, H>::check(&skr.hs, &skr.bs, t) {
            return None;
        }
        skr.hs
            .iter()
            .enumerate()
            .find_map(|(hi, &h)| {
                let i_ast = H::h(t, h);
                if skr.bs.view_bits::<Lsb0>()[i_ast] {
                    None
                } else {
                    Some((hi, i_ast))
                }
            })
            .and_then(|(hi, i_ast)| {
                GgmMultiPuncPrf::<LAMBDA, N, KD>::eval(&skr.ski, i_ast)
                    .map(|sk| SE::dec(&sk, ct[hi]))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::thread_rng;

    use crate::bloom::SipH;
    use crate::multi_punc_prf::HmacSha256GgmKeyDerive;
    use crate::symm_enc::CryptoSecretBox;

    const LAMBDA: usize = 32;
    const BN: usize = 8192;
    const N: usize = 8192 * 8;
    const HN: usize = 3;
    const PLAINTXT: &[u8] = b"Hello, world!";
    const TAGS: &[&[u8]] = &[b"myl7", b"alice", b"bob", b"nobody"];

    #[test]
    fn test_sre_enc_then_dec_ok() {
        let msk =
            SreImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GgmKeyDerive, CryptoSecretBox>::kgen(
                &mut thread_rng(),
            );
        let ct =
            SreImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GgmKeyDerive, CryptoSecretBox>::enc(
                &msk, PLAINTXT, TAGS[0],
            );
        let skr =
            SreImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GgmKeyDerive, CryptoSecretBox>::krev(
                &msk,
                &TAGS[1..],
            );
        let m =
            SreImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GgmKeyDerive, CryptoSecretBox>::dec(
                &skr,
                ct.iter()
                    .map(|cti| cti.as_ref())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                TAGS[0],
            );
        assert_eq!(m, Some(PLAINTXT.to_vec()));
    }

    #[test]
    fn test_sre_enc_then_dec_punctured() {
        let msk =
            SreImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GgmKeyDerive, CryptoSecretBox>::kgen(
                &mut thread_rng(),
            );
        let ct =
            SreImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GgmKeyDerive, CryptoSecretBox>::enc(
                &msk, PLAINTXT, TAGS[1],
            );
        let skr =
            SreImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GgmKeyDerive, CryptoSecretBox>::krev(
                &msk,
                &TAGS[1..],
            );
        let m =
            SreImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GgmKeyDerive, CryptoSecretBox>::dec(
                &skr,
                ct.iter()
                    .map(|cti| cti.as_ref())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                TAGS[1],
            );
        assert_eq!(m, None);
    }
}
