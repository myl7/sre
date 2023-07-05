// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

pub mod bf;
pub mod mf;
pub mod se;

/// `SRE`. API of symmetric revocable encryption.
pub trait SRE {
    /// `SRE.KGen`
    fn kgen();
    /// `SRE.Enc`
    fn enc();
    /// `SRE.KRev`
    fn krev();
    /// `SRE.Dec`
    fn dec();
}
