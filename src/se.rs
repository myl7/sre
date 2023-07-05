// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

use aes::cipher::generic_array::{typenum, GenericArray};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

/// `SE`. API of standard symmetric encryption.
pub trait SE<const LAMBDA: usize> {
    /// `SE.Gen`. Unused.
    // fn gen() -> [u8; LAMBDA];
    /// `SE.Enc`.
    /// `sk` is the secret key.
    /// `m` is the plaintext. Modified in-place.
    fn enc(sk: &[u8; LAMBDA], m: &mut [u8]);
    /// `SE.Dec`.
    /// `sk` is the secret key.
    /// `ct` is the ciphertext. Modified in-place.
    fn dec(sk: &[u8; LAMBDA], ct: &mut [u8]);
}

/// AES128 / AES256 as symmetric encryption implementation.
/// `SKN` is the key size. Can only be 16 (for 128) / 32 (for 256).
pub struct AES<const SKN: usize>;

impl SE<16> for AES<16> {
    fn enc(sk: &[u8; 16], m: &mut [u8]) {
        assert_eq!(m.len(), 16);
        let sk_arr = GenericArray::<u8, typenum::U16>::from_slice(&sk[..]);
        let cipher = Aes128::new(sk_arr);
        cipher.encrypt_block(GenericArray::from_mut_slice(m));
    }

    fn dec(sk: &[u8; 16], ct: &mut [u8]) {
        assert_eq!(ct.len(), 16);
        let sk_arr = GenericArray::<u8, typenum::U16>::from_slice(&sk[..]);
        let cipher = Aes128::new(sk_arr);
        cipher.decrypt_block(GenericArray::from_mut_slice(ct));
    }
}

impl SE<32> for AES<32> {
    fn enc(sk: &[u8; 32], m: &mut [u8]) {
        assert_eq!(m.len(), 16);
        let sk_arr = GenericArray::<u8, typenum::U32>::from_slice(&sk[..]);
        let cipher = Aes256::new(sk_arr);
        cipher.encrypt_block(GenericArray::from_mut_slice(m));
    }

    fn dec(sk: &[u8; 32], ct: &mut [u8]) {
        assert_eq!(ct.len(), 16);
        let sk_arr = GenericArray::<u8, typenum::U32>::from_slice(&sk[..]);
        let cipher = Aes256::new(sk_arr);
        cipher.decrypt_block(GenericArray::from_mut_slice(ct));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAINTEXT: &[u8; 16] = b"0123456789abcdef";

    #[test]
    fn test_aes128_enc_then_dec_ok() {
        let sk = b"\xab'\xfa\x10\xf2i?_\xaf\xeb\xba>4@\xdd\xe6";
        let mut m = PLAINTEXT.to_owned();
        AES::<16>::enc(sk, &mut m);
        AES::<16>::dec(sk, &mut m);
        assert_eq!(m, *PLAINTEXT);
    }

    #[test]
    fn test_aes256_enc_then_dec_ok() {
        let sk = b"t\xd3\xa4\x1fy\x81H\x102\x00\x96\xe4\xee\x1a\xe5\xc92\x8a\x1b\xf8\x0f\x88\xb0;[\r\xcdB\x17\xca\x8c\xd7";
        let mut m = PLAINTEXT.to_owned();
        AES::<32>::enc(sk, &mut m);
        AES::<32>::dec(sk, &mut m);
        assert_eq!(m, *PLAINTEXT);
    }
}
