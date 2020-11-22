/// Provides the decrypting `Write` part
/// Targets another Writer, sending decrypted data to it

use std::io::{Write};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, NewAead};

// Size of a 'block'
use super::BLOCK_LENGTH;
use crate::encryption::{DATA_LENGTH, nonce_from_u128};

// State of the writer
// Nonce: waiting to get the initial nonce
// Data: decrypting data blocks
// Done: Returns only Ok(0)
#[derive(Debug, PartialEq)]
enum DecWriteState {
    Nonce,
    Data,
    Done,
}

pub struct DecryptingWriter<W: Write> {
    target: W, // Inner write, this will receive decrypted data
    aead: XChaCha20Poly1305,
    state: DecWriteState,
    nonce: u128, // Current nonce (counter)
    input_buffer: [u8; 3*BLOCK_LENGTH as usize], // Triple length buffer
    received: usize,
}

impl<W: Write> Write for DecryptingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        match self.state {
            // Receive the initial nonce value
            DecWriteState::Nonce => {
                let read_len = buf.len().min(16-self.received);
                self.input_buffer[self.received..self.received+read_len].copy_from_slice(&buf[..read_len]);
                self.received += read_len;
                if self.received == 16 {
                    let mut be_bytes = [0u8; 16];
                    be_bytes.copy_from_slice(&self.input_buffer[..16]);
                    self.nonce = u128::from_be_bytes(be_bytes);
                    self.state = DecWriteState::Data;
                    self.received = 0;
                }

                Ok(read_len)
            }
            // Receive and decrypt data
            DecWriteState::Data => {
                // Read into our internal buffer. At most, enough to fill the buffer
                let read_len = buf.len().min(self.input_buffer.len()-self.received);
                self.input_buffer[self.received..self.received+read_len].copy_from_slice(&buf[..read_len]);
                self.received += read_len;

                // If the input buffer is full, try to decrypt
                // Since padding can span two blocks, we need 3 blocks to check:
                // 1. We have the actual data block
                // 2. We have the full-pad block, which contains pad length
                // 3. If there were more data, we know block 1 isn't padded
                if self.received == self.input_buffer.len() {
                    // We got 3 blocks. Block 1 is not padded, decrypt and write it
                    let mut nonce_arr = vec![0u8; 8];
                    nonce_arr.append(&mut self.nonce.to_be_bytes().to_vec());
                    let nonce = XNonce::from_slice(&nonce_arr);
                    self.nonce += 1;
                    let plaintext = self.aead.decrypt(nonce, &self.input_buffer[..BLOCK_LENGTH])
                        .expect("Decryption failed!");
                    self.target.write_all(&plaintext)?;
                    // Move current items s.t. block 2 is now block 1, block 3 is now block 2
                    self.input_buffer.rotate_left(BLOCK_LENGTH as usize);
                    self.received -= BLOCK_LENGTH;
                } else if read_len == 0 { // 0-size buffer, assume we get no more input and finish up
                    self.state = DecWriteState::Done;
                    // Ensure we have the right amount of bytes
                    if self.received % BLOCK_LENGTH != 0 {
                        panic!("Decryption received an incorrect amount of input");
                    }
                    // Two cases here
                    // We only have one block (small file, <= BLOCK_LENGTH)
                    // We have two blocks (file size >= BLOCK_LENGTH)
                    if self.received == BLOCK_LENGTH as usize { // 1 block only
                        let nonce = nonce_from_u128(self.nonce);
                        self.nonce += 1;
                        let plaintext = self.aead.decrypt(&nonce, &self.input_buffer[..BLOCK_LENGTH])
                            .expect("Decryption failed!");
                        let mut be_bytes = [0u8; 4];
                        be_bytes.copy_from_slice(&plaintext[plaintext.len()-4..]);
                        let pad_amount = u32::from_be_bytes(be_bytes) as usize;
                        self.target.write_all(&plaintext[..plaintext.len()-pad_amount])?;
                    } else if self.received == 2*BLOCK_LENGTH as usize { // 2 blocks
                        let nonce = nonce_from_u128(self.nonce);
                        self.nonce += 1;
                        let plaintext1 = self.aead.decrypt(&nonce, &self.input_buffer[..BLOCK_LENGTH])
                            .expect("Decryption failed!");
                        let nonce = nonce_from_u128(self.nonce);
                        self.nonce += 1;
                        let plaintext2 = self.aead.decrypt(&nonce, &self.input_buffer[BLOCK_LENGTH..2*BLOCK_LENGTH])
                            .expect("Decryption failed!");
                        let mut be_bytes = [0u8; 4];
                        be_bytes.copy_from_slice(&plaintext2[plaintext2.len()-4..]);
                        let mut pad_amount = u32::from_be_bytes(be_bytes) as usize;
                        if pad_amount >= DATA_LENGTH { // Full block pad, ignore plaintext2
                            pad_amount -= DATA_LENGTH;
                            self.target.write_all(&plaintext1[..plaintext1.len()-pad_amount])?;
                        } else {
                            self.target.write_all(&plaintext1)?;
                            self.target.write_all(&plaintext2[..plaintext2.len()-pad_amount])?;
                        }
                    } else {
                        panic!("Invalid amount of data!");
                    }
                }

                Ok(read_len)
            }
            // Done, return 0's
            DecWriteState::Done => {
                Ok(0)
            }
        }

    }

    fn flush(&mut self) -> Result<(),std::io::Error> {
        self.write(&[])?;
        Ok(())
    }
}

impl<W: Write> DecryptingWriter<W> {
    pub fn target(writer: W, key: &Key) -> Self {
        DecryptingWriter {
            target: writer,
            aead: XChaCha20Poly1305::new(key),
            state: DecWriteState::Nonce,
            nonce: 0,
            input_buffer: [0u8; 3*BLOCK_LENGTH as usize],
            received: 0,
        }
    }
}