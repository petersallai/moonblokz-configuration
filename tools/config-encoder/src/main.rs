//! `config-encoder` — turns parameter overrides into signed chain-config content.
//!
//! ```text
//! config-encoder [INPUT.cfg] --key KEY.hex [-o OUTPUT.bin]
//! ```
//!
//! Reads the override description from `INPUT.cfg`, or from standard input when
//! no path is given. `--key` names a file holding node #0's private key as hex.
//! Writes raw payload bytes to `OUTPUT.bin` when `-o` is given, and otherwise
//! prints a hexdump — the form the content appears in when it is reviewed before
//! a chain is founded.

use std::io::{Read, Write};
use std::process::ExitCode;

use moonblokz_config_encoder::encode;
use moonblokz_crypto::PRIVATE_KEY_SIZE;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("config-encoder: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut key_path: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-o" | "--output" => {
                output = Some(args.next().ok_or("-o needs a path")?);
            }
            "-k" | "--key" => {
                key_path = Some(args.next().ok_or("--key needs a path")?);
            }
            "-h" | "--help" => {
                println!("usage: config-encoder [INPUT.cfg] --key KEY.hex [-o OUTPUT.bin]");
                return Ok(());
            }
            other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
            path => {
                if input.replace(path.to_string()).is_some() {
                    return Err("only one input path is accepted".to_string());
                }
            }
        }
    }

    let key_path = key_path.ok_or("--key is required: the content is signed by node #0")?;
    let private_key = read_key(&key_path)?;

    let source = match &input {
        Some(path) => {
            std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?
        }
        None => {
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|e| format!("cannot read standard input: {e}"))?;
            buffer
        }
    };

    let payload = encode(&source, private_key).map_err(|error| match &input {
        Some(path) => format!("{path}:{error}"),
        None => error.to_string(),
    })?;

    match output {
        Some(path) => {
            std::fs::write(&path, &payload).map_err(|e| format!("cannot write {path}: {e}"))?
        }
        None => {
            let hex: Vec<String> = payload.iter().map(|byte| format!("{byte:02X}")).collect();
            let mut stdout = std::io::stdout();
            writeln!(stdout, "{}", hex.join(" ")).map_err(|e| e.to_string())?;
        }
    }

    eprintln!("config-encoder: {} bytes", payload.len());
    Ok(())
}

/// Reads a private key written as hex, ignoring whitespace.
fn read_key(path: &str) -> Result<[u8; PRIVATE_KEY_SIZE], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != PRIVATE_KEY_SIZE * 2 {
        return Err(format!(
            "{path}: expected {} hex digits, found {}",
            PRIVATE_KEY_SIZE * 2,
            digits.len()
        ));
    }
    let mut key = [0u8; PRIVATE_KEY_SIZE];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{path}: `{}` is not hex", &digits[index * 2..index * 2 + 2]))?;
    }
    Ok(key)
}
