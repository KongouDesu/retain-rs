// Tests for the encryption module
// Note that some of these assume that BLOCK_LENGTH = 8192, though it should work with other values

#[cfg(test)]
mod tests {
    use crate::encryption::reader::EncryptingReader;
    use chacha20poly1305::Key;
    use crate::encryption::{BLOCK_LENGTH, get_nonces_required, get_encrypted_size};
    use std::io::{Cursor, Read, Write};
    use crate::encryption::writer::DecryptingWriter;

    #[test]
    fn test_write_to_file() {
        let filebuf = vec![1u8;43863];
        let mut reader = EncryptingReader::wrap(Cursor::new(filebuf),
                                                Key::from_slice(b"an example very very secret key."),
                                                0, get_nonces_required(43863));

        let mut buf = [0u8; 4096];
        let mut out = std::fs::File::create("encrypted.dat").unwrap();
        let mut written = 0;
        while let Ok(n) = reader.read(&mut buf) {
            if n != 0 {
                out.write_all(&mut buf[..n]).unwrap();
                written += n;
                if written > 100000 {
                    panic!("Infinite loop(?)");
                }
            } else {
                break;
            }
        }
        assert_eq!(get_encrypted_size(43863u64),written as u64);
    }

    #[test]
    // Verify the output from the encrypting reader is as expected
    fn test_output_length_small() {
        // This should be nonce (16 bytes) + 8192 (data + padding)
        // We can fit 8192 - 16 (MAC) - 4 (Padding length) at most in 1 block
        for x in 0..8173 {
            let buf = vec![1u8; x];
            assert_eq!(1, get_nonces_required(x as u64));
            let mut reader = EncryptingReader::wrap(Cursor::new(buf),
                                                    Key::from_slice(b"an example very very secret key."),
                                                    0, 1);
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
            assert_eq!(get_encrypted_size(x as u64),read as u64);
        }
    }

    #[test]
    // Verify the output from the encrypting reader is as expected
    fn test_output_length_scheme_needs_extra() {
        // Should be nonce (16 bytes) + 16384 (data + padding)
        // These 3 (8173, 8174 and 8175) and do not have enough room for the padding scheme
        // As a result they should pad BLOCK_LENGTH + an extra 1-3 bytes for the scheme to fit
        for x in 8173..8176 {
            let buf = vec![1u8;x];
            assert_eq!(2, get_nonces_required(x as u64));
            let mut reader = EncryptingReader::wrap(Cursor::new(buf),
                                                    Key::from_slice(b"an example very very secret key."),
                                                    0, 2);
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
            assert_eq!(get_encrypted_size(x as u64),read as u64);
        }
    }

    #[test]
    // Verify the output from the encrypting reader is as expected
    fn test_output_length_long() {
        // Should be nonce (16 bytes) + 16384 (data + padding)
        for x in 8176..13384-16 {
            let buf = vec![1u8; x];
            assert_eq!(2, get_nonces_required(x as u64));
            let mut reader = EncryptingReader::wrap(Cursor::new(buf),
                                                    Key::from_slice(b"an example very very secret key."),
                                                    0, 2);
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
            assert_eq!(get_encrypted_size(x as u64),read as u64);
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        // Encrypt
        let buf = std::fs::File::open("secret.jpg").unwrap();
        let len = std::fs::metadata("secret.jpg").unwrap().len();
        let mut reader = EncryptingReader::wrap(buf,
                                                Key::from_slice(b"an example very very secret key."),
                                                0, get_nonces_required(len));

        let mut buf = [0u8; 4096];
        let mut out = std::fs::File::create("secret.encrypted").unwrap();
        let mut written = 0u64;
        let mut read = 0u64;
        while let Ok(n) = reader.read(&mut buf) {
            if n != 0 {
                out.write_all(&mut buf[..n]).unwrap();
                written += n as u64;
                if written > len*2 {
                    panic!("Wrote way too much");
                }
            } else {
                break;
            }
        }
        out.sync_all().unwrap();
        let mut file = std::fs::File::open("secret.encrypted").unwrap();
        let mut outf = std::fs::File::create("secret.decrypted").unwrap();
        let mut writer = DecryptingWriter::target(&outf, Key::from_slice(b"an example very very secret key."));

        let mut buf = [0u8; 4096];
        while let Ok(n) = file.read(&mut buf) {
            if n != 0 {
                writer.write_all(&buf[..n]).unwrap();
            } else {
                break;
            }
        }
        writer.flush().unwrap();
        outf.sync_all().unwrap();

        let original = std::fs::read("secret.jpg").unwrap();
        let decrypted = std::fs::read("secret.decrypted").unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_same_file_repeated_differs() {
        for i in 1..3 {
            {
                let buf = std::fs::File::open("secret.jpg").unwrap();
                let len = std::fs::metadata("secret.jpg").unwrap().len();
                let mut reader = EncryptingReader::wrap(buf,
                                                        Key::from_slice(b"an example very very secret key."),
                                                        i*get_nonces_required(len), get_nonces_required(len));

                let mut buf = [0u8; 4096];
                let mut out = std::fs::File::create(format!("secret{}.encrypted",i)).unwrap();
                let mut written = 0u64;
                let mut read = 0;
                while let Ok(n) = reader.read(&mut buf) {
                    read += n;
                    if n != 0 {
                        out.write_all(&mut buf[..n]).unwrap();
                        written += n as u64;
                        if written > len * 2 {
                            panic!("Wrote way too much");
                        }
                    } else {
                        break;
                    }
                }
                assert_eq!(get_encrypted_size(len as u64),read as u64);
                out.sync_all().unwrap();
            }
        }

        let s1 = std::fs::read("secret1.encrypted").unwrap();
        let s2 = std::fs::read("secret2.encrypted").unwrap();
        assert_ne!(s1,s2);
    }

    #[test]
    fn test_bulk_encrypt_decrypt() {
        for x in 0..BLOCK_LENGTH*4 {
            // Encrypt
            let mut orig_data = vec![7u8; x];
            let indata = Cursor::new(&mut orig_data);
            let mut reader = EncryptingReader::wrap(indata,
                                                    Key::from_slice(b"an example very very secret key."),
                                                    0, get_nonces_required(x as u64));

            let mut buf = [0u8; 4096];
            let mut read = 0;
            let mut written = 0u64;
            let mut decr: Vec<u8> = Vec::with_capacity(x);
            let outdata = Cursor::new(&mut decr);
            let mut writer = DecryptingWriter::target(outdata, Key::from_slice(b"an example very very secret key."));

            while let Ok(n) = reader.read(&mut buf) {
                read += n;
                if n != 0 {
                    writer.write_all(&mut buf[..n]).unwrap();
                    written += n as u64;
                    if written > (get_nonces_required(x as u64) as usize*BLOCK_LENGTH + 16) as u64 {
                        panic!("Wrote way too much x{} ({} expected, got {})", x, (get_nonces_required(x as u64) as usize*BLOCK_LENGTH + 16), written);
                    }
                } else {
                    break;
                }
            }
            writer.flush().unwrap();

            assert_eq!(orig_data, decr);
            assert_eq!(get_encrypted_size(x as u64),read as u64);
        }
    }

}