use chacha20poly1305::{XNonce};

/// This module defines the functionality required to encrypt and decrypt files
///
/// Encryption uses the XChaCha20Poly1305 algorithm
/// The nonces are in counter mode. Files are broken into blocks each with a fixed size.
/// At the start of an encrypted file, the initial nonce value is written, unencrypted and unauthenticated
/// Every subsequent block simply increments this value by 1
///
/// If there is not enough data to fill a block, it will be padded to fit
/// The last 4 bytes of an encrypted file is the big-endian u32 number of padded bytes
/// Padding is anywhere from 4 to BLOCK_LENGTH bytes
///
/// We can fit BLOCK_LENGTH-16 data-bytes in a block
/// If the last block has more than BLOCK_LENGTH-16-4 data-bytes, it will pad a full block + 1 to 3 bytes
/// This is because it can't fit the amount padded otherwise


// Length of a block of data
// The reader encrypts and pads data to a multiple of this value
// The writer decrypts and un-pads based on this
//
// Note that the MAC is 16 bytes, thus we encrypt BLOCK_LENGTH-16 bytes at a time
// This lets us write BLOCK_LENGTH chunks at a time
// As a result, this value must be strictly greater than 16
pub const BLOCK_LENGTH: usize = 8192;
pub const DATA_LENGTH: usize = BLOCK_LENGTH-16;

pub mod reader;
pub mod writer;

mod test;

/// Computes the required amount of nonces to encrypt 'length' bytes
///
/// This accounts for the encryption overhead
#[allow(dead_code)]
pub fn get_nonces_required(length: u64) -> u128 {
    return ((length+3)/(BLOCK_LENGTH as u64-16)+1) as u128;
}

fn nonce_from_u128(number: u128) -> XNonce {
    let mut nonce_arr = vec![0u8; 8];
    nonce_arr.append(&mut number.to_be_bytes().to_vec());
    XNonce::from_slice(&nonce_arr).to_owned()
}