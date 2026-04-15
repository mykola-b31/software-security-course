use clap::{Parser, ValueEnum};
use std::error::Error;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};

const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const ITERATIONS: usize = 100_000;

#[derive(Parser, Debug)]
#[command(name = "cryptor_aes_gcm")]
#[command(about = "Програма для шифрування файлів (AES-256-GCM)", long_about = None)]
struct Cli {
    /// Operation mode: encrypt or decrypt
    #[arg(value_enum)]
    mode: CliMode,

    /// Path to the input file
    #[arg(short, long)]
    input: String,

    /// Path to the output file
    #[arg(short, long)]
    output: String,

    /// Password (minimum 10 characters)
    #[arg(short = 'p', long)]
    password: String,
}

#[derive(Clone, Debug, ValueEnum)]
enum CliMode {
    Encrypt,
    Decrypt,
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE], Box<dyn Error>> {
    let mut key = [0u8; KEY_SIZE];
    pbkdf2_hmac(
        password.as_bytes(),
        salt,
        ITERATIONS,
        MessageDigest::sha256(),
        &mut key,
    )?;
    Ok(key)
}

fn encrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn Error>> {
    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    let mut salt = [0u8; SALT_SIZE];
    let mut iv = [0u8; IV_SIZE];
    rand_bytes(&mut salt)?;
    rand_bytes(&mut iv)?;

    let key = derive_key(password, &salt)?;

    output_file.write_all(&salt)?;
    output_file.write_all(&iv)?;

    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv))?;

    let mut buffer = vec![0u8; 1024 * 1024];
    let mut out_buffer = vec![0u8; 1024 * 1024 + cipher.block_size()];

    println!("Encrypting file...");
    loop {
        let bytes_read = input_file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let count = crypter.update(&buffer[..bytes_read], &mut out_buffer)?;
        output_file.write_all(&out_buffer[..count])?;
    }

    let count = crypter.finalize(&mut out_buffer)?;
    output_file.write_all(&out_buffer[..count])?;

    let mut tag = [0u8; TAG_SIZE];
    crypter.get_tag(&mut tag)?;
    output_file.write_all(&tag)?;

    println!("File successfully encrypted!");
    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), Box<dyn Error>> {
    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    let file_size = input_file.metadata()?.len();
    let meta_size = (SALT_SIZE + IV_SIZE + TAG_SIZE) as u64;

    if file_size < meta_size {
        return Err("File is too small or corrupted".into());
    }

    let mut salt = [0u8; SALT_SIZE];
    let mut iv = [0u8; IV_SIZE];
    input_file.read_exact(&mut salt)?;
    input_file.read_exact(&mut iv)?;

    let mut tag = [0u8; TAG_SIZE];
    input_file.seek(SeekFrom::End(-(TAG_SIZE as i64)))?;
    input_file.read_exact(&mut tag)?;

    input_file.seek(SeekFrom::Start((SALT_SIZE + IV_SIZE) as u64))?;

    let key = derive_key(password, &salt)?;

    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))?;

    crypter.set_tag(&tag)?;

    let mut buffer = vec![0u8; 1024 * 1024];
    let mut out_buffer = vec![0u8; 1024 * 1024 + cipher.block_size()];

    let mut bytes_to_read = file_size - meta_size;

    println!("Decrypting file...");
    while bytes_to_read > 0 {
        let chunk_size = std::cmp::min(bytes_to_read, buffer.len() as u64) as usize;
        let bytes_read = input_file.read(&mut buffer[..chunk_size])?;
        if bytes_read == 0 {
            break;
        }

        let count = crypter.update(&buffer[..bytes_read], &mut out_buffer)?;
        output_file.write_all(&out_buffer[..count])?;

        bytes_to_read -= bytes_read as u64;
    }

    let count = crypter
        .finalize(&mut out_buffer)
        .map_err(|_| "Authentication error: Incorrect password or corrupted file!")?;
    output_file.write_all(&out_buffer[..count])?;

    println!("File successfully decrypted!");
    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if cli.password.len() < 10 {
        eprintln!("Error: Password must contain at least 10 characters!");
        std::process::exit(1);
    }

    let result = match cli.mode {
        CliMode::Encrypt => encrypt_file(&cli.input, &cli.output, &cli.password),
        CliMode::Decrypt => decrypt_file(&cli.input, &cli.output, &cli.password),
    };

    if let Err(e) = result {
        eprintln!("Critical error: {}", e);
        std::process::exit(1);
    }
}
