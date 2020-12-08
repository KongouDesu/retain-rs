use crate::config::Config;
use clap::ArgMatches;
use crate::colorutil::printcoln;
use termcolor::Color;
use std::io::{Read, Write};
use crate::encryption::{key_from_file, get_nonces_required};
use crate::encryption::reader::EncryptingReader;
use rand::{thread_rng, Rng};
use crate::encryption::writer::DecryptingWriter;

pub fn encrypt(config: &mut Config, args: Option<&ArgMatches>) {
    let args = args.unwrap(); // Guaranteed by Clap

    if args.is_present("keygen") {
        let mut output = match std::fs::File::create(args.value_of("keygen").unwrap()) {
            Ok(f) => f,
            Err(err) => {
                printcoln(Color::Red, format!("Error: Keyfile could not be opened ({:?})", err));
                return;
            }
        };
        let mut rng = thread_rng();
        let mut key_bytes = [0u8; 32];
        rng.try_fill(&mut key_bytes).expect("Failed to generate key");
        output.write_all(&mut key_bytes).unwrap();
        config.secret_key = Some(args.value_of("keygen").unwrap().to_string());
        config.save();
    }

    // Ensure a secret key is defined
    match config.secret_key {
        Some(_) => (),
        None => {
            printcoln(Color::Red, "Error: No secret key set");
            return;
        }
    }

    if let Some(mut files) = args.values_of("encrypt") {
        let infile = files.next().unwrap();
        let outfile = files.next().unwrap();
        let input = match std::fs::File::open(infile) {
            Ok(f) => f,
            Err(err) => {
                printcoln(Color::Red, format!("Error: Input file {} could not be opened ({:?})", infile, err));
                return;
            }
        };
        let inp_size = std::fs::metadata(infile).unwrap().len();
        let mut output = match std::fs::File::create(outfile) {
            Ok(f) => f,
            Err(err) => {
                printcoln(Color::Red, format!("Error: Output file {} could not be opened ({:?})", outfile, err));
                return;
            }
        };

        let key = match key_from_file(config.secret_key.as_ref().unwrap()) {
            Ok(k) => k,
            Err(err) => {
                printcoln(Color::Red, format!("Error: Secret key could not be read ({:?})", err));
                return;
            }
        };

        let (start_nonce,allocated) = {
            let req = get_nonces_required(inp_size);
            let start = config.consume_nonces(req);
            (start, req)
        };
        let mut reader = EncryptingReader::wrap(input, &key, start_nonce, allocated);

        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n != 0 {
                output.write_all(&mut buf[..n]).unwrap();
            } else {
                break;
            }
        }
        printcoln(Color::Green, "Successfully encrypted file!");
    }

    if let Some(mut files) = args.values_of("decrypt") {
        let infile = files.next().unwrap();
        let outfile = files.next().unwrap();
        let mut input = match std::fs::File::open(infile) {
            Ok(f) => f,
            Err(err) => {
                printcoln(Color::Red, format!("Error: Input file {} could not be opened ({:?})", infile, err));
                return;
            }
        };
        let output = match std::fs::File::create(outfile) {
            Ok(f) => f,
            Err(err) => {
                printcoln(Color::Red, format!("Error: Output file {} could not be opened ({:?})", outfile, err));
                return;
            }
        };

        let key = match key_from_file(config.secret_key.as_ref().unwrap()) {
            Ok(k) => k,
            Err(err) => {
                printcoln(Color::Red, format!("Error: Secret key could not be read ({:?})", err));
                return;
            }
        };

        let mut writer = DecryptingWriter::target(output, &key);

        let mut buf = [0u8; 4096];
        while let Ok(n) = input.read(&mut buf) {
            writer.write_all(&mut buf[..n]).unwrap();
            if n == 0 {
                writer.flush().unwrap();
                break;
            }
        }


        printcoln(Color::Green, "Successfully decrypted file!");
    }
}