// Copyright (C) myl7
// SPDX-License-Identifier: Apache-2.0

use crypto_secretbox::aead::{Aead, AeadCore, KeyInit, OsRng};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};

/// `SE`. API of standard symmetric encryption.
pub trait SE<const LAMBDA: usize> {
    /// `SE.Gen`. Unused.
    // fn gen() -> [u8; LAMBDA];
    /// `SE.Enc`.
    /// `sk` is the secret key.
    /// `m` is the plaintext.
    fn enc(sk: &[u8; LAMBDA], m: &[u8]) -> Vec<u8>;
    /// `SE.Dec`.
    /// `sk` is the secret key.
    /// `ct` is the ciphertext.
    fn dec(sk: &[u8; LAMBDA], ct: &[u8]) -> Vec<u8>;
}

// NaCl `crypto_secretbox` as symmetric encryption, which uses XSalsa20-Poly1305.
pub struct CryptoSecretBox;

impl SE<{ XSalsa20Poly1305::KEY_SIZE }> for CryptoSecretBox {
    fn enc(sk: &[u8; XSalsa20Poly1305::KEY_SIZE], m: &[u8]) -> Vec<u8> {
        let key = Key::from_slice(sk);
        let cipher = XSalsa20Poly1305::new(key);
        let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
        let mut ciphertext = cipher.encrypt(&nonce, m).unwrap().to_vec();
        let mut result = nonce.to_vec();
        result.append(&mut ciphertext);
        result
    }

    fn dec(sk: &[u8; XSalsa20Poly1305::KEY_SIZE], ct: &[u8]) -> Vec<u8> {
        let key = Key::from_slice(sk);
        let cipher = XSalsa20Poly1305::new(key);
        let nonce = Nonce::from_slice(&ct[..XSalsa20Poly1305::NONCE_SIZE]);
        let ciphertext = &ct[XSalsa20Poly1305::NONCE_SIZE..];
        cipher.decrypt(nonce, ciphertext).unwrap().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAINTEXT: &[u8; 16] = b"0123456789abcdef";

    #[test]
    fn test_secretbox_enc_then_dec_ok() {
        let sk = b"t\xd3\xa4\x1fy\x81H\x102\x00\x96\xe4\xee\x1a\xe5\xc92\x8a\x1b\xf8\x0f\x88\xb0;[\r\xcdB\x17\xca\x8c\xd7";
        let ct = CryptoSecretBox::enc(sk, PLAINTEXT);
        let m = CryptoSecretBox::dec(sk, &ct);
        assert_eq!(&m, PLAINTEXT);
    }
}
