/// Provides the encryption `Read` part
/// Wraps another Reader, encrypting everything from it

use std::io::{Read, Write};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, NewAead};

// Size of a 'block'
use super::BLOCK_LENGTH;
use crate::encryption::{DATA_LENGTH, nonce_from_u128};

// Represents the state of the reader. It progresses through them in order
// Nonce: write the initial nonce to the file
// Data: read and encrypt inner data
// Pad: pad (and encrypt) to the goal length
// Done: once output buffer has been read, return 0
#[derive(Debug, PartialEq)]
enum EncReadState {
    Nonce,
    Data,
    Pad,
    Done,
}

pub struct EncryptingReader<R: Read> {
    inner: R, // Inner reader, data from this will be encrypted
    aead: XChaCha20Poly1305,
    state: EncReadState,
    nonce: u128, // Current nonce (counter)
    nonce_max: u128, // The maximum allowed value of 'nonce'
    input_buffer: [u8; DATA_LENGTH as usize], // Buffered data read from 'inner', until we have a full block of data
    output_buffer: [u8; BLOCK_LENGTH as usize], // Buffered output, in case our supplied buffer isn't large enough
    read: usize, // Tracks amount read to the input buffer
    written: usize, // Tracks amount returned from the output buffer
    total_size: u64, // Tracks how much we've read, in total, from the inner reader
    pad_extra: u32, // Extra padding, see padding code below
}

impl<R: Read> Read for EncryptingReader<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, std::io::Error> {
        // Check if we have any pending output
        // This is the case if 'written' is between 1 and BLOCK_LENGTH-1
        if self.written != 0 && self.written != BLOCK_LENGTH as usize {
            let written = buf.write(&self.output_buffer[self.written..])?;
            self.written += written;
            return Ok(written);
        }

        // Make sure we didn't run out of nonces before finishing
        if self.nonce >= self.nonce_max && self.state != EncReadState::Done {
            panic!("Ran out of allocated nonces!");
        }

        match self.state {
            // Return the nonce, unencrypted
            // If the buffer isn't at least 16 bytes then IDK go buy a bigger one?
            EncReadState::Nonce => {
                let bytes = self.nonce.to_be_bytes();
                buf.write_all(&bytes)?;
                self.state = EncReadState::Data;
                Ok(bytes.len())
            }
            // Encrypt and return data from inner reader
            EncReadState::Data => {
                // Keep trying to read until we fill our input buffer or reach the end of it
                self.read = 0;
                while let Ok(n) = self.inner.read(&mut self.input_buffer[self.read..]) {
                    if n == 0 { // Nothing more to read in the inner reader
                        break;
                    }
                    self.read += n;
                }
                // If we didn't read a full block, start padding
                if self.read != self.input_buffer.len() {
                    self.state = EncReadState::Pad;
                    return Ok(self.read(buf)?);
                }
                // At this point, the buffer contains exactly DATA_LENGTH bytes
                let nonce = nonce_from_u128(self.nonce);
                self.nonce += 1;
                let ciphertext = self.aead.encrypt(&nonce, self.input_buffer.as_ref()).expect("Encryption failed!");
                self.output_buffer.copy_from_slice(&ciphertext);
                self.written = 0;
                self.written += buf.write(&self.output_buffer)?;
                self.total_size += BLOCK_LENGTH as u64;
                Ok(self.written)
            } // Add (encrypted) padding
            EncReadState::Pad => {
                // First we need to determine amount of bytes to pad
                // This is enough bytes to get us to DATA_LEN bytes of data
                // If this is less than 4 bytes we cannot fit the amount of padding added
                // In that case we pad that amount + a full block
                let pad_amount: u32;
                if self.pad_extra == 0 { // First pass, how much pad is needed
                    pad_amount = ((DATA_LENGTH as u64) - self.read as u64) as u32;
                } else { // If we needed less than 1-3 bytes of padding, add a full block
                    pad_amount = DATA_LENGTH as u32;
                }

                // Due to the BLOCK_LENGTH being 4 bytes, we need at least 4 bytes pad for the scheme
                // If we don't have that:
                // 1. Pad this block (0 to 3 bytes padding)
                // 2. Save how many bytes we padded to 'self.pad_extra'
                // 3. Encrypt the block
                // 4. Set it as output buffer
                // 5. Increment total_size by amount padded and return
                // Next time read is called, after finishing the output buffer, we will hit the pad case again, but:
                // * total_size is now a multiple of BLOCK_LENGTH, so another full block of pad is added
                // * We use BLOCK_LENGTH+self.pad_extra as the amount padded
                if pad_amount < 4 {
                    self.pad_extra = pad_amount;
                    let nonce = nonce_from_u128(self.nonce);
                    self.nonce += 1;
                    (&mut self.input_buffer[self.read..]).write(vec![0u8; pad_amount as usize].as_ref())?;
                    let ciphertext = self.aead.encrypt(&nonce, self.input_buffer.as_ref()).expect("Encryption failed!");
                    self.output_buffer.copy_from_slice(&ciphertext);
                    self.written = 0;
                    self.written += buf.write(&self.output_buffer)?;
                    self.total_size += BLOCK_LENGTH as u64;
                    self.read = 0; // We've accounted for it now
                    return Ok(self.written);
                }

                // Here we know that the amount to pad is 4 to BLOCK_LENGTH bytes and thus fits in 1 output_buffer
                // We also know that we have enough room for the scheme
                // Note that we have to add 'self.pad_extra' to the amount padded, since we might have hit the above case
                let pad_num: u32 = pad_amount + self.pad_extra;
                // Write pad_amount-4 0's. This leaves 4 bytes for amount padded
                let idx = self.input_buffer.len();
                (&mut self.input_buffer[self.read..idx-4]).copy_from_slice(vec![0u8; (pad_amount - 4) as usize].as_ref());
                // Write the amount of padding applied

                (&mut self.input_buffer[idx-4..]).copy_from_slice(&pad_num.to_be_bytes());

                // Encrypt, write to output buffer etc.
                let nonce = nonce_from_u128(self.nonce);
                self.nonce += 1;
                let ciphertext = self.aead.encrypt(&nonce, self.input_buffer.as_ref()).expect("Encryption failed!");
                self.output_buffer.copy_from_slice(&ciphertext);
                self.written = 0;
                self.written += buf.write(&self.output_buffer)?;
                self.total_size += BLOCK_LENGTH as u64;
                self.state = EncReadState::Done;
                Ok(self.written)
            }
            EncReadState::Done => {
                Ok(0)
            }
        }
    }
}

impl<R: Read> EncryptingReader<R> {
    // Wrap another reader, encrypting with 'key'.
    // Requires the initial nonce and the amount of nonces it may use
    // For subsequents calls, start_nonce should be at least `start_nonce+allocated_nonces´ to avoid repeat use
    pub fn wrap(reader: R, key: &Key, start_nonce: u128, allocated_nonces: u128) -> Self {
        EncryptingReader {
            inner: reader,
            aead: XChaCha20Poly1305::new(key),
            state: EncReadState::Nonce,
            nonce: start_nonce,
            nonce_max: start_nonce+allocated_nonces,
            input_buffer: [0u8; (BLOCK_LENGTH-16) as usize],
            output_buffer: [0u8; BLOCK_LENGTH as usize],
            read: 0,
            written: 0,
            total_size: 0,
            pad_extra: 0,
        }
    }
}