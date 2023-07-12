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
pub trait Sre<const LAMBDA: usize, const HN: usize, Msk, Skr> {
    /// `SRE.KGen`
    fn kgen<R>(&self, rng: &mut R) -> Msk
    where
        R: Rng + ?Sized;
    /// `SRE.Enc`.
    fn enc(&self, msk: &Msk, m: &[u8], t: &[u8]) -> [Vec<u8>; HN];
    /// `SRE.KRev`
    fn krev(&self, msk: &Msk, r: &[&[u8]]) -> Skr;
    /// `SRE.Dec`
    fn dec(&self, skr: &Skr, ct: [&[u8]; HN], t: &[u8]) -> Option<Vec<u8>>;
}

/// Symmetric revocable encryption implementation.
///
/// To avoid `#![feature(generic_const_exprs)]`, it is **your responsibility** to ensure `N = BN * 8`.
pub struct SreImpl<
    const LAMBDA: usize,
    const BN: usize,
    const N: usize,
    const HN: usize,
    H,
    KD,
    SymmEncT,
> where
    H: BloomH<BN>,
    KD: GgmKeyDerive<LAMBDA>,
    SymmEncT: SymmEnc<LAMBDA>,
{
    bf: BloomImpl<BN, HN, H>,
    mf: GgmMultiPuncPrf<LAMBDA, N, KD>,
    se: SymmEncT,
}

impl<const LAMBDA: usize, const BN: usize, const N: usize, const HN: usize, H, KD, SE>
    SreImpl<LAMBDA, BN, N, HN, H, KD, SE>
where
    H: BloomH<BN>,
    KD: GgmKeyDerive<LAMBDA>,
    SE: SymmEnc<LAMBDA>,
{
    pub fn new(bf: BloomImpl<BN, HN, H>, mf: GgmMultiPuncPrf<LAMBDA, N, KD>, se: SE) -> Self {
        Self { bf, mf, se }
    }
}

/// `msk`. Secret key of symmetric revocable encryption.
pub struct Msk<const LAMBDA: usize, const BN: usize, const HN: usize> {
    pub sk: GgmPrfKey<LAMBDA>,
    pub hs: [usize; HN],
    pub bs: [u8; BN],
}

/// `$sk_R$`
pub struct Skr<const LAMBDA: usize, const BN: usize, const HN: usize, HS> {
    pub ski: GgmPuncKey<LAMBDA>,
    pub hs: [HS; HN],
    pub bs: [u8; BN],
}

impl<const LAMBDA: usize, const BN: usize, const N: usize, const HN: usize, H, KD, SE>
    Sre<LAMBDA, HN, Msk<LAMBDA, BN, HN>, Skr<LAMBDA, BN, HN, usize>>
    for SreImpl<LAMBDA, BN, N, HN, H, KD, SE>
where
    H: BloomH<BN>,
    KD: GgmKeyDerive<LAMBDA>,
    SE: SymmEnc<LAMBDA>,
{
    fn kgen<R>(&self, rng: &mut R) -> Msk<LAMBDA, BN, HN>
    where
        R: Rng + ?Sized,
    {
        let (hs, bs) = self.bf.gen();
        let sk = self.mf.setup(rng);
        Msk::<LAMBDA, BN, HN> { sk, hs, bs }
    }

    fn enc(&self, msk: &Msk<LAMBDA, BN, HN>, m: &[u8], t: &[u8]) -> [Vec<u8>; HN] {
        (0..HN)
            .map(|j| self.bf.h().hash(t, msk.hs[j]))
            .map(|i| self.mf.f(&msk.sk, i).unwrap())
            .map(|sk| self.se.enc(&sk, m))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn krev(&self, msk: &Msk<LAMBDA, BN, HN>, r: &[&[u8]]) -> Skr<LAMBDA, BN, HN, usize> {
        assert!(r.len() <= N);
        let mut bs_buf = msk.bs.to_owned();
        r.iter().for_each(|t| self.bf.upd(&msk.hs, &mut bs_buf, t));
        let is: Vec<_> = bs_buf.view_bits::<Lsb0>().iter_ones().collect();
        let punc_key = self.mf.punc(&msk.sk, &is);
        Skr {
            ski: punc_key,
            hs: msk.hs.to_owned(),
            bs: bs_buf,
        }
    }

    fn dec(&self, skr: &Skr<LAMBDA, BN, HN, usize>, ct: [&[u8]; HN], t: &[u8]) -> Option<Vec<u8>> {
        if self.bf.check(&skr.hs, &skr.bs, t) {
            return None;
        }
        skr.hs
            .iter()
            .enumerate()
            .find_map(|(hi, &h)| {
                let i_ast = self.bf.h().hash(t, h);
                if skr.bs.view_bits::<Lsb0>()[i_ast] {
                    None
                } else {
                    Some((hi, i_ast))
                }
            })
            .and_then(|(hi, i_ast)| {
                self.mf
                    .eval(&skr.ski, i_ast)
                    .map(|sk| self.se.dec(&sk, ct[hi]))
            })
    }
}

#[cfg(all(
    test,
    feature = "bloom-h",
    feature = "ggm-key-derive",
    feature = "symm-enc"
))]
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
        let se = CryptoSecretBox::new();
        let kd = HmacSha256GgmKeyDerive::new();
        let mf = GgmMultiPuncPrf::<LAMBDA, N, _>::new(kd);
        let h_impl = SipH::<BN>::new();
        let bf = BloomImpl::<BN, HN, _>::new(h_impl);
        let sre = SreImpl::<LAMBDA, BN, N, HN, _, _, _>::new(bf, mf, se);
        let msk = sre.kgen(&mut thread_rng());
        let ct = sre.enc(&msk, PLAINTXT, TAGS[0]);
        let skr = sre.krev(&msk, &TAGS[1..]);
        let m = sre.dec(
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
        let se = CryptoSecretBox::new();
        let kd = HmacSha256GgmKeyDerive::new();
        let mf = GgmMultiPuncPrf::<LAMBDA, N, _>::new(kd);
        let h_impl = SipH::<BN>::new();
        let bf = BloomImpl::<BN, HN, _>::new(h_impl);
        let sre = SreImpl::<LAMBDA, BN, N, HN, _, _, _>::new(bf, mf, se);
        let msk = sre.kgen(&mut thread_rng());
        let ct = sre.enc(&msk, PLAINTXT, TAGS[1]);
        let skr = sre.krev(&msk, &TAGS[1..]);
        let m = sre.dec(
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
