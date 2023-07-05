// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

//! See [`SRE`]

pub mod bf;
pub mod mf;
pub mod se;

use std::marker::PhantomData;

use bitvec::prelude::*;
use rand::prelude::*;

use crate::bf::{BFImpl, BFImplH, BF};
use crate::mf::{GGMKeyDerive, GGMPRFKey, GGMPuncKey, GGMPuncPRF, MF};
use crate::se::SE;

/// `SRE`. API of symmetric revocable encryption.
///
/// See [`bf::BF`] for `BN` and `HN`.
pub trait SRE<const LAMBDA: usize, const HN: usize, MSK, SKR> {
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
/// To avoid #![feature(generic_const_exprs)], it is your responsibility to ensure `N = BN * 8`.
pub struct SREImpl<
    const LAMBDA: usize,
    const BN: usize,
    const N: usize,
    const HN: usize,
    H,
    KD,
    SEImpl,
> where
    H: BFImplH<BN>,
    KD: GGMKeyDerive<LAMBDA>,
    SEImpl: SE<LAMBDA>,
{
    _h: PhantomData<H>,
    _kd: PhantomData<KD>,
    _se: PhantomData<SEImpl>,
}

/// `msk`. Secret key of Symmetric revocable encryption.
pub struct MSKImpl<const LAMBDA: usize, const BN: usize, const HN: usize> {
    pub sk: GGMPRFKey<LAMBDA>,
    pub hs: [usize; HN],
    pub bs: [u8; BN],
}

/// `$sk_R$`
pub struct SKRImpl<const LAMBDA: usize, const BN: usize, const HN: usize, HS> {
    pub ski: GGMPuncKey<LAMBDA>,
    pub hs: [HS; HN],
    pub bs: [u8; BN],
}

impl<const LAMBDA: usize, const BN: usize, const N: usize, const HN: usize, H, KD, SEImpl>
    SRE<LAMBDA, HN, MSKImpl<LAMBDA, BN, HN>, SKRImpl<LAMBDA, BN, HN, usize>>
    for SREImpl<LAMBDA, BN, N, HN, H, KD, SEImpl>
where
    H: BFImplH<BN>,
    KD: GGMKeyDerive<LAMBDA>,
    SEImpl: SE<LAMBDA>,
{
    fn kgen<R>(rng: &mut R) -> MSKImpl<LAMBDA, BN, HN>
    where
        R: Rng + ?Sized,
    {
        let (hs, bs) = BFImpl::<BN, HN, H>::gen();
        let sk = GGMPuncPRF::<LAMBDA, N, KD>::setup(rng);
        MSKImpl::<LAMBDA, BN, HN> { sk, hs, bs }
    }

    fn enc(msk: &MSKImpl<LAMBDA, BN, HN>, m: &[u8], t: &[u8]) -> [Vec<u8>; HN] {
        let punc_key = GGMPuncPRF::<LAMBDA, N, KD>::punc(&msk.sk, &[]);
        (0..HN)
            .into_iter()
            .map(|j| H::h(t, msk.hs[j]))
            .map(|i| GGMPuncPRF::<LAMBDA, N, KD>::eval(&punc_key, i).unwrap())
            .map(|sk| SEImpl::enc(&sk, m))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn krev(msk: &MSKImpl<LAMBDA, BN, HN>, r: &[&[u8]]) -> SKRImpl<LAMBDA, BN, HN, usize> {
        assert!(r.len() <= N);
        let mut bs_buf = msk.bs.to_owned();
        r.iter()
            .for_each(|t| BFImpl::<BN, HN, H>::upd(&msk.hs, &mut bs_buf, t));
        let is: Vec<_> = bs_buf.view_bits::<Lsb0>().iter_ones().collect();
        let punc_key = GGMPuncPRF::<LAMBDA, N, KD>::punc(&msk.sk, &is);
        SKRImpl {
            ski: punc_key,
            hs: msk.hs.to_owned(),
            bs: bs_buf,
        }
    }

    fn dec(skr: &SKRImpl<LAMBDA, BN, HN, usize>, ct: [&[u8]; HN], t: &[u8]) -> Option<Vec<u8>> {
        // We do not use this because we need the intermediate hash results
        // if BFImpl::<BN, HN, H>::check(&skr.hs, &skr.bs, t) {
        //     return None;
        // }
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
                GGMPuncPRF::<LAMBDA, N, KD>::eval(&skr.ski, i_ast)
                    .map(|sk| SEImpl::dec(&sk, &ct[hi]))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::thread_rng;

    use crate::bf::SipH;
    use crate::mf::HmacSha256GGMKeyDerive;
    use crate::se::CryptoSecretBox;

    const LAMBDA: usize = 32;
    const BN: usize = 8192;
    const N: usize = 8192 * 8;
    const HN: usize = 3;
    const PLAINTXT: &[u8] = b"Hello, world!";
    const TAGS: &[&[u8]] = &[b"myl7", b"alice", b"bob", b"nobody"];

    #[test]
    fn test_sre_enc_then_dec_ok() {
        let msk =
            SREImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GGMKeyDerive, CryptoSecretBox>::kgen(
                &mut thread_rng(),
            );
        let ct =
            SREImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GGMKeyDerive, CryptoSecretBox>::enc(
                &msk, PLAINTXT, TAGS[0],
            );
        let skr =
            SREImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GGMKeyDerive, CryptoSecretBox>::krev(
                &msk,
                &TAGS[1..],
            );
        let m =
            SREImpl::<LAMBDA, BN, N, HN, SipH<BN>, HmacSha256GGMKeyDerive, CryptoSecretBox>::dec(
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
}
