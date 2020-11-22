#[cfg(test)]
mod tests {
    use crate::encryption::traits::EncryptingReader;
    use chacha20poly1305::Key;
    use crate::encryption::{BLOCK_LENGTH,get_nonces_required};
    use std::io::{Cursor, Read, Write};

    #[test]
    fn test_write_to_file() {
        let buf = vec![1u8;43863];
        let mut reader = EncryptingReader::wrap(Cursor::new(buf),
                                                Key::from_slice(b"an example very very secret key."),
                                                0, get_nonces_required(43863));

        let mut buf = [0u8; 4096];
        let mut out = std::fs::File::create("encrypted.dat").unwrap();
        let mut written = 0;
        while let Ok(n) = reader.read(&mut buf) {
            if n != 0 {
                out.write_all(&mut buf[..n]);
                written += n;
                if written > 100000 {
                    panic!("Infinite loop(?)");
                }
            } else {
                break;
            }
        }
    }

    #[test]
    // Verify the output from the encrypting reader is as expected
    fn test_output_length_small() {
        // This should be nonce (16 bytes) + 8192 (data + padding)
        for x in 0..8176 {
            let buf = vec![1u8; x];
            let mut reader = EncryptingReader::wrap(Cursor::new(buf),
                                                    Key::from_slice(b"an example very very secret key."),
                                                    0, get_nonces_required(x as u64));
            let mut out = [0u8; 32768]; // Sufficiently large buffer
            let mut read = 0;
            while let Ok(n) = reader.read(&mut out[read..]) {
                if n != 0 {
                    read += n;
                } else {
                    break;
                }
            }
            assert_eq!(read, 8192 + 16);
        }
    }

    #[test]
    // Verify the output from the encrypting reader is as expected
    fn test_output_length_scheme_needs_extra() {
        // Should be nonce (16 bytes) + 16384 (data + padding)
        // These 4 are from 8192 to 8195 and do not have enough room for the padding scheme
        // As a result they should pad BLOCK_LENGTH + an extra 1-4 bytes for the scheme to fit
        for x in 8176..8180 {
            let buf = vec![1u8;x];
            let mut reader = EncryptingReader::wrap(Cursor::new(buf),
                                                    Key::from_slice(b"an example very very secret key."),
                                                    0, get_nonces_required(x as u64));
            let mut out = [0u8; 32768]; // Sufficiently large buffer
            let mut read = 0;
            while let Ok(n) = reader.read(&mut out[read..]) {
                if n != 0 {
                    read += n;
                } else {
                    break;
                }

            }
            assert_eq!(read, 16384+16);
        }
    }

    #[test]
    // Verify the output from the encrypting reader is as expected
    fn test_output_length_long() {
        // Should be nonce (16 bytes) + 16384 (data + padding)
        for x in 8180..13384-16 {
            let buf = vec![1u8; x];
            let mut reader = EncryptingReader::wrap(Cursor::new(buf),
                                                    Key::from_slice(b"an example very very secret key."),
                                                    0, get_nonces_required(x as u64));
            let mut out = [0u8; 32768]; // Sufficiently large buffer
            let mut read = 0;
            while let Ok(n) = reader.read(&mut out[read..]) {
                if n != 0 {
                    read += n;
                } else {
                    break;
                }
            }
            assert_eq!(read, 16384 + 16);
        }
    }

}