// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

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
/// See [`bf::BF`] for `BN` and `HN`.
pub trait SRE<const LAMBDA: usize, const BN: usize, const HN: usize, MSK, HS, BS, SKR> {
    /// `SRE.KGen`
    fn kgen<R>(rng: &mut R) -> MSK
    where
        R: Rng + ?Sized;
    /// `SRE.Enc`.
    fn enc(msk: &MSK, hs: &[HS; HN], m: &[u8], t: &[u8]) -> [Vec<u8>; HN];
    /// `SRE.KRev`
    fn krev(msk: &MSK, hs: &[HS; HN], bs: &BS, r: &[&[u8]]) -> SKR;
    /// `SRE.Dec`
    fn dec(skr: SKR, ct: [&[u8]; HN], t: &[u8]) -> Option<Vec<u8>>;
}

/// Symmetric revocable encryption implementation.
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
    H: BFImplH,
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

/// $sk_R$
pub struct SKRImpl<const LAMBDA: usize, const BN: usize, const HN: usize, HS> {
    pub ski: GGMPuncKey<LAMBDA>,
    pub hs: [HS; HN],
    pub bs: [u8; BN],
}

impl<const LAMBDA: usize, const BN: usize, const N: usize, const HN: usize, H, KD, SEImpl>
    SRE<LAMBDA, BN, HN, MSKImpl<LAMBDA, BN, HN>, usize, [u8; BN], SKRImpl<LAMBDA, BN, HN, usize>>
    for SREImpl<LAMBDA, BN, N, HN, H, KD, SEImpl>
where
    H: BFImplH,
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

    fn enc(msk: &MSKImpl<LAMBDA, BN, HN>, hs: &[usize; HN], m: &[u8], t: &[u8]) -> [Vec<u8>; HN] {
        (0..HN)
            .into_iter()
            .map(|j| H::h(t, hs[j]))
            .map(|i| {
                let punc_key = GGMPuncPRF::<LAMBDA, N, KD>::punc(&msk.sk, &[]);
                GGMPuncPRF::<LAMBDA, N, KD>::eval(&punc_key, i).unwrap()
            })
            .map(|sk| {
                // TODO: SE ouputs Vec
                let mut m_buf = m.to_vec();
                SEImpl::enc(&sk, &mut m_buf);
                m_buf
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn krev(
        msk: &MSKImpl<LAMBDA, BN, HN>,
        hs: &[usize; HN],
        bs: &[u8; BN],
        r: &[&[u8]],
    ) -> SKRImpl<LAMBDA, BN, HN, usize> {
        assert!(r.len() <= N);
        let mut bs_buf = bs.to_owned();
        r.iter()
            .for_each(|t| BFImpl::<BN, HN, H>::upd(hs, &mut bs_buf, t));
        let is: Vec<_> = bs_buf.view_bits::<Lsb0>().iter_ones().collect();
        let punc_key = GGMPuncPRF::<LAMBDA, N, KD>::punc(&msk.sk, &is);
        SKRImpl {
            ski: punc_key,
            hs: hs.to_owned(),
            bs: bs_buf,
        }
    }

    fn dec(skr: SKRImpl<LAMBDA, BN, HN, usize>, ct: [&[u8]; HN], t: &[u8]) -> Option<Vec<u8>> {
        if !BFImpl::<BN, HN, H>::check(&skr.hs, &skr.bs, t) {
            return None;
        }
        match skr.bs.view_bits::<Lsb0>().first_zero() {
            Some(i) => GGMPuncPRF::<LAMBDA, N, KD>::eval(&skr.ski, i).map(|sk| {
                let mut m_buf = ct[0].to_vec();
                SEImpl::dec(&sk, &mut m_buf);
                m_buf
            }),
            None => None,
        }
    }
}
