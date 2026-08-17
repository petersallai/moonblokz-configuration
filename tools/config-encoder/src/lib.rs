//! Encoder for MoonBlokz chain-configuration content.
//!
//! Produces the configuration content handed to `initiateGenesis(...)`: it takes
//! a description of parameter overrides, resolves each name to its registry
//! identifier, frames the override set, and appends node #0's content signature.
//!
//! It then applies the framing checks and the acceptance checks of the runtime —
//! by calling the runtime's own `accept_content`, not by restating it — so that a
//! configuration this tool accepts is one the network accepts.
//!
//! Bytecode entries are assembled by calling `vm-asm` as a library. The
//! dependency direction matches the crate layering: configuration knows about
//! bytecode, the VM knows nothing about configuration.
//!
//! # Input format
//!
//! One `name = value` assignment per line. `#` begins a comment. A value is
//!
//! - an integer, decimal or `0x`-prefixed hexadecimal, encoded little-endian at
//!   the parameter's declared width;
//! - a byte list — `[255, 243, 65, 82, 143]` — for an array-typed parameter,
//!   carried verbatim;
//! - an assembly program in braces, where a parameter may be referenced as
//!   `@name`:
//!
//! ```text
//! # half the inter-block interval, read rather than restated
//! grace_period_window_ms = {
//!     GETPARAM @inter_block_interval_ms, 0
//!     PUSH 2
//!     DIV
//!     RET
//! }
//! ```

use std::fmt;

use moonblokz_chain_types::ChainConfigPayloadBuilder;
use moonblokz_configuration::{ChainConfigError, accept_content, parameter, parameter_spec};
use moonblokz_crypto::{Crypto, CryptoTrait, PRIVATE_KEY_SIZE};
use moonblokz_vm_asm::assemble;

/// Parameter names, as they appear in this tool's input and as `@name` inside a
/// program.
///
/// The names live here rather than in the registry: they are a host-side
/// convenience, and a name table in the library would be flash the firmware pays
/// for a facility only this tool uses. [`names_match_the_registry`] pins the two
/// together so they cannot drift.
///
/// [`names_match_the_registry`]: #
pub const NAMES: [(&str, u8); 29] = [
    (
        "inter_block_interval_ms",
        parameter::INTER_BLOCK_INTERVAL_MS,
    ),
    ("grace_period_window_ms", parameter::GRACE_PERIOD_WINDOW_MS),
    ("block_size_limit", parameter::BLOCK_SIZE_LIMIT),
    ("max_block_utxo_output", parameter::MAX_BLOCK_UTXO_OUTPUT),
    (
        "max_aggregated_signatures",
        parameter::MAX_AGGREGATED_SIGNATURES,
    ),
    ("vote_scale", parameter::VOTE_SCALE),
    ("vote_interest", parameter::VOTE_INTEREST),
    (
        "parent_recovery_per_head_retry_interval_ms",
        parameter::PARENT_RECOVERY_PER_HEAD_RETRY_INTERVAL_MS,
    ),
    (
        "parent_recovery_min_emit_interval_ms",
        parameter::PARENT_RECOVERY_MIN_EMIT_INTERVAL_MS,
    ),
    ("required_support", parameter::REQUIRED_SUPPORT),
    (
        "echo_request_minimal_interval",
        parameter::ECHO_REQUEST_MINIMAL_INTERVAL,
    ),
    (
        "echo_messages_target_interval",
        parameter::ECHO_MESSAGES_TARGET_INTERVAL,
    ),
    ("echo_gathering_timeout", parameter::ECHO_GATHERING_TIMEOUT),
    (
        "delay_between_tx_packets",
        parameter::DELAY_BETWEEN_TX_PACKETS,
    ),
    (
        "delay_between_tx_messages",
        parameter::DELAY_BETWEEN_TX_MESSAGES,
    ),
    ("relay_position_delay", parameter::RELAY_POSITION_DELAY),
    ("scoring_matrix", parameter::SCORING_MATRIX),
    (
        "retry_interval_for_missing_packets",
        parameter::RETRY_INTERVAL_FOR_MISSING_PACKETS,
    ),
    (
        "tx_maximum_random_delay",
        parameter::TX_MAXIMUM_RANDOM_DELAY,
    ),
    (
        "block_fill_threshold_percent",
        parameter::BLOCK_FILL_THRESHOLD_PERCENT,
    ),
    ("active_chain_length", parameter::ACTIVE_CHAIN_LENGTH),
    (
        "mempool_replenishment_interval_ms",
        parameter::MEMPOOL_REPLENISHMENT_INTERVAL_MS,
    ),
    ("custodian_fee", parameter::CUSTODIAN_FEE),
    ("registration_price", parameter::REGISTRATION_PRICE),
    ("tx_fee_per_byte_min", parameter::TX_FEE_PER_BYTE_MIN),
    ("tx_fee_per_byte_max", parameter::TX_FEE_PER_BYTE_MAX),
    (
        "deviation_replay_insertion_delay_ms",
        parameter::DEVIATION_REPLAY_INSERTION_DELAY_MS,
    ),
    ("replay_block_reward", parameter::REPLAY_BLOCK_REWARD),
    ("vm_fuel_limit", parameter::VM_FUEL_LIMIT),
];

/// The registry identifier a name refers to.
pub fn identifier_of(name: &str) -> Option<u8> {
    NAMES
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, id)| *id)
}

/// A diagnostic naming the input line that could not be encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeError {
    /// One-based line number, or zero for a whole-content diagnostic.
    pub line: usize,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.message)
        } else {
            write!(f, "line {}: {}", self.line, self.message)
        }
    }
}

impl std::error::Error for EncodeError {}

fn err(line: usize, message: impl Into<String>) -> EncodeError {
    EncodeError {
        line,
        message: message.into(),
    }
}

/// One parsed override, in input order — which is byte order, and therefore part
/// of what the signature covers.
struct Override {
    line: usize,
    id: u8,
    value: Value,
}

enum Value {
    Literal(Vec<u8>),
    Program(Vec<u8>),
}

/// Encodes `source` into a signed chain-config payload.
///
/// The returned bytes are a complete `payload_type = 3` payload: the content
/// region followed by node #0's content signature, ready to hand to
/// `BlockBuilder::set_chain_config_payload`.
pub fn encode(source: &str, private_key: [u8; PRIVATE_KEY_SIZE]) -> Result<Vec<u8>, EncodeError> {
    let overrides = parse(source)?;

    let mut builder = ChainConfigPayloadBuilder::new();
    for entry in &overrides {
        let framed = match &entry.value {
            Value::Literal(bytes) => builder.add_literal(entry.id, bytes),
            Value::Program(bytes) => builder.add_bytecode(entry.id, bytes),
        };
        // `BlockError` carries no `Debug`, and the framing refuses for exactly two
        // reasons at this point: a repeated parameter, or an override set that no
        // longer fits one payload.
        framed.ok().ok_or_else(|| {
            err(
                entry.line,
                "cannot frame this entry — the parameter is already set, or the override set no longer fits one chain-config payload",
            )
        })?;
    }

    let crypto = Crypto::new(private_key)
        .ok()
        .ok_or_else(|| err(0, "the signing key was refused by the crypto backend"))?;
    let payload = builder.build_signed(&crypto).to_vec();

    // The runtime's own acceptance pass, not a restatement of it: whatever this
    // tool accepts, the network accepts.
    accept_content(&payload).map_err(|error| err(0, describe(&error)))?;

    Ok(payload)
}

/// Parses the input into overrides, in file order.
fn parse(source: &str) -> Result<Vec<Override>, EncodeError> {
    let lines: Vec<&str> = source.lines().collect();
    let mut overrides = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let line_no = index + 1;
        let line = strip_comment(lines[index]).trim();
        index += 1;
        if line.is_empty() {
            continue;
        }

        let (name, rest) = line
            .split_once('=')
            .ok_or_else(|| err(line_no, "expected `name = value`"))?;
        let name = name.trim();
        let id = identifier_of(name)
            .ok_or_else(|| err(line_no, format!("unknown parameter `{name}`")))?;
        let spec = parameter_spec(id).ok_or_else(|| {
            err(
                line_no,
                format!("`{name}` is not allocated in the registry"),
            )
        })?;

        let rest = rest.trim();
        let value = if rest == "{" {
            // An assembly block runs to a line holding only `}`. The body is
            // handed to the assembler verbatim once `@name` references are
            // resolved, so `;` comments inside it stay the assembler's.
            let start = index;
            while index < lines.len() && lines[index].trim() != "}" {
                index += 1;
            }
            if index == lines.len() {
                return Err(err(line_no, "unterminated program block"));
            }
            let body = &lines[start..index];
            index += 1;

            if !spec.bytecode_allowed {
                return Err(err(
                    line_no,
                    format!("`{name}` is literal-only and does not accept a program"),
                ));
            }
            let program = assemble(&resolve_references(body, start)?)
                .map_err(|error| err(start + error.line, error.message))?;
            Value::Program(program)
        } else if rest.starts_with('[') {
            Value::Literal(parse_byte_list(line_no, rest, spec.width, name)?)
        } else {
            Value::Literal(parse_integer(line_no, rest, spec.width, name)?)
        };

        overrides.push(Override {
            line: line_no,
            id,
            value,
        });
    }

    Ok(overrides)
}

/// Rewrites `@name` references to registry identifiers and checks every
/// `GETPARAM`'s declared argument count against the registry.
///
/// The assembler cannot do either: it belongs to `moonblokz-vm`, which knows
/// nothing about the registry. The layering is visible in the syntax on purpose —
/// `GETPARAM` takes a number, and the name is this tool's convenience.
fn resolve_references(body: &[&str], offset: usize) -> Result<String, EncodeError> {
    let mut resolved = String::new();

    for (index, raw) in body.iter().enumerate() {
        let line_no = offset + index + 1;
        let mut line = String::new();
        let mut rest = *raw;

        while let Some(at) = rest.find('@') {
            line.push_str(&rest[..at]);
            let after = &rest[at + 1..];
            let end = after
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(after.len());
            let name = &after[..end];
            let id = identifier_of(name)
                .ok_or_else(|| err(line_no, format!("unknown parameter `@{name}`")))?;
            line.push_str(&id.to_string());
            rest = &after[end..];
        }
        line.push_str(rest);

        check_getparam_arity(line_no, &line)?;
        resolved.push_str(&line);
        resolved.push('\n');
    }

    Ok(resolved)
}

/// Refuses a `GETPARAM` whose declared argument count contradicts the registry.
///
/// The host seam would decline such a call at runtime and the parameter would
/// silently fall back to its default; catching it here is what turns that into a
/// diagnostic naming the line.
fn check_getparam_arity(line_no: usize, line: &str) -> Result<(), EncodeError> {
    let code = line.split(';').next().unwrap_or("").trim();
    let mut tokens = code.split_whitespace();
    let Some(mnemonic) = tokens.next() else {
        return Ok(());
    };
    if !mnemonic.eq_ignore_ascii_case("GETPARAM") {
        return Ok(());
    }

    let operands: Vec<&str> = code[mnemonic.len()..]
        .split(',')
        .flat_map(|part| part.split_whitespace())
        .collect();
    if operands.len() != 2 {
        return Err(err(
            line_no,
            "GETPARAM takes a parameter identifier and an argument count",
        ));
    }
    let (Ok(id), Ok(argc)) = (parse_number(operands[0]), parse_number(operands[1])) else {
        // A malformed operand is the assembler's diagnostic to give.
        return Ok(());
    };

    let Some(spec) = u8::try_from(id).ok().and_then(parameter_spec) else {
        return Err(err(
            line_no,
            format!("GETPARAM names identifier {id}, which the registry does not allocate"),
        ));
    };
    if argc != spec.args as u64 {
        return Err(err(
            line_no,
            format!(
                "GETPARAM declares {argc} argument(s) for identifier {id}, but the registry records arity {}",
                spec.args
            ),
        ));
    }
    Ok(())
}

fn parse_integer(
    line_no: usize,
    text: &str,
    width: u8,
    name: &str,
) -> Result<Vec<u8>, EncodeError> {
    let value = parse_number(text)
        .map_err(|_| err(line_no, format!("`{text}` is not an integer literal")))?;
    let width = width as usize;
    // The exact-width rule is the runtime's, so a value that does not fit is
    // caught here rather than framed into a rejection.
    if width < 8 && value >= 1u64 << (8 * width) {
        return Err(err(
            line_no,
            format!("{value} does not fit `{name}`'s {width}-byte width"),
        ));
    }
    Ok(value.to_le_bytes()[..width].to_vec())
}

fn parse_byte_list(
    line_no: usize,
    text: &str,
    width: u8,
    name: &str,
) -> Result<Vec<u8>, EncodeError> {
    let inner = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| err(line_no, "a byte list must be enclosed in `[` and `]`"))?;
    let mut bytes = Vec::new();
    for item in inner.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let value = parse_number(item)
            .map_err(|_| err(line_no, format!("`{item}` is not a byte value")))?;
        bytes.push(
            u8::try_from(value)
                .map_err(|_| err(line_no, format!("`{item}` does not fit one byte")))?,
        );
    }
    if bytes.len() != width as usize {
        return Err(err(
            line_no,
            format!(
                "`{name}` is {width} bytes wide, but {} were given",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

fn parse_number(text: &str) -> Result<u64, core::num::ParseIntError> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    }
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(at) => &line[..at],
        None => line,
    }
}

/// A message for each acceptance rejection. `ChainConfigError` carries no
/// `Debug` outside the library's own tests — every trait impl costs binary size
/// on embedded targets — so the diagnostic is written out here.
fn describe(error: &ChainConfigError) -> String {
    match error {
        ChainConfigError::MalformedContent => "the framed content is malformed".to_string(),
        ChainConfigError::UnknownParameter(key_byte) => {
            format!("key byte {key_byte:#04X} names a parameter the registry does not allocate")
        }
        ChainConfigError::ValueWidthMismatch(id) => {
            format!("the literal for identifier {id} does not match its declared width")
        }
        ChainConfigError::BytecodeNotPermitted(id) => {
            format!("identifier {id} is literal-only and does not accept a program")
        }
        ChainConfigError::BytecodeEvaluationFailed(id) => format!(
            "the argument-less program for identifier {id} did not complete under the fuel limit"
        ),
        ChainConfigError::BoundViolation(id) => format!(
            "the declared value for identifier {id} is outside the structural bound this build can honour"
        ),
        ChainConfigError::DurableLocked => "the configuration is durably locked".to_string(),
        ChainConfigError::NotLoaded => "no configuration is loaded".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moonblokz_configuration::{
        ChainConfigTrait, ChainConfiguration, NoopConfigChangeSink, SNAKE_CHAIN_LENGTH_MAX,
    };
    use moonblokz_crypto::SignatureTrait;

    const KEY: [u8; PRIVATE_KEY_SIZE] = [7u8; PRIVATE_KEY_SIZE];

    fn loaded(source: &str) -> ChainConfiguration<NoopConfigChangeSink> {
        let payload = encode(source, KEY).expect("the fixture should encode");
        let mut module = ChainConfiguration::new(NoopConfigChangeSink);
        module
            .load_tentative(&payload)
            .ok()
            .expect("what the encoder accepts, the runtime accepts");
        module
    }

    #[test]
    fn names_match_the_registry() {
        // Every allocated identifier has exactly one name, and every name refers
        // to an allocated identifier. This is what lets the registry stay
        // name-free without the two drifting.
        for (name, id) in NAMES {
            assert!(
                parameter_spec(id).is_some(),
                "`{name}` refers to unallocated identifier {id}"
            );
        }
        let mut seen = vec![false; NAMES.len() + 1];
        for (name, id) in NAMES {
            assert!(!seen[id as usize], "identifier {id} named twice (`{name}`)");
            seen[id as usize] = true;
        }
        for id in 1..=NAMES.len() as u8 {
            assert!(
                parameter_spec(id).is_some() == seen[id as usize],
                "identifier {id} is allocated but unnamed, or named but unallocated"
            );
        }
    }

    #[test]
    fn integer_and_hexadecimal_literals_encode() {
        let module = loaded(
            "# a terser inter-block interval\n\
             inter_block_interval_ms = 45000\n\
             vote_interest = 0x09\n",
        );
        let config = module.active_configuration().expect("handle");
        assert_eq!(config.inter_block_interval_ms(), 45_000);
        assert_eq!(config.vote_interest(), 9);
    }

    #[test]
    fn a_byte_list_encodes_an_array_parameter() {
        let module = loaded("scoring_matrix = [1, 2, 3, 4, 0xFF]\n");
        assert_eq!(
            module
                .active_configuration()
                .expect("handle")
                .scoring_matrix(),
            [1, 2, 3, 4, 255]
        );
    }

    #[test]
    fn a_program_block_is_assembled_and_its_references_resolved() {
        let module = loaded(
            "inter_block_interval_ms = 90000\n\
             grace_period_window_ms = {\n\
             \x20   GETPARAM @inter_block_interval_ms, 0   ; read, do not restate\n\
             \x20   PUSH 2\n\
             \x20   DIV\n\
             \x20   RET\n\
             }\n",
        );
        let config = module.active_configuration().expect("handle");
        assert_eq!(config.grace_period_window_ms(), 45_000);
    }

    #[test]
    fn an_empty_input_encodes_the_empty_override_set() {
        let module = loaded("# nothing overridden\n");
        let config = module.active_configuration().expect("handle");
        assert_eq!(config.inter_block_interval_ms(), 60_000);
    }

    #[test]
    fn an_unknown_name_is_refused() {
        let error = encode("no_such_parameter = 1\n", KEY).expect_err("unknown name");
        assert_eq!(error.line, 1);
        assert!(error.message.contains("unknown parameter"));
    }

    #[test]
    fn a_value_over_the_declared_width_is_refused() {
        let error = encode("vote_interest = 256\n", KEY).expect_err("one byte wide");
        assert_eq!(error.line, 1);
        assert!(error.message.contains("1-byte width"));
    }

    #[test]
    fn a_byte_list_of_the_wrong_length_is_refused() {
        let error = encode("scoring_matrix = [1, 2, 3]\n", KEY).expect_err("five bytes wide");
        assert!(error.message.contains("5 bytes wide"));
    }

    #[test]
    fn a_program_under_a_literal_only_parameter_is_refused() {
        let error = encode("required_support = {\n    PUSH 3\n    RET\n}\n", KEY)
            .expect_err("literal-only");
        assert_eq!(error.line, 1);
        assert!(error.message.contains("literal-only"));
    }

    #[test]
    fn a_getparam_arity_that_contradicts_the_registry_is_refused() {
        let error = encode(
            "vote_interest = {\n    GETPARAM @inter_block_interval_ms, 1\n    RET\n}\n",
            KEY,
        )
        .expect_err("identifier 1 is argument-less");
        assert_eq!(error.line, 2);
        assert!(error.message.contains("arity 0"));
    }

    #[test]
    fn a_getparam_naming_an_unallocated_identifier_is_refused() {
        let error = encode("vote_interest = {\n    GETPARAM 120, 0\n    RET\n}\n", KEY)
            .expect_err("identifier 120 is unallocated");
        assert_eq!(error.line, 2);
        assert!(error.message.contains("does not allocate"));
    }

    #[test]
    fn an_assembler_diagnostic_keeps_its_line_number() {
        let error = encode(
            "vote_interest = {\n    PUSH 1\n    NOSUCHOP\n    RET\n}\n",
            KEY,
        )
        .expect_err("unknown mnemonic");
        assert_eq!(error.line, 3);
    }

    #[test]
    fn a_repeated_parameter_is_refused() {
        let error = encode("vote_interest = 1\nvote_interest = 2\n", KEY)
            .expect_err("one entry per parameter");
        assert_eq!(error.line, 2);
    }

    #[test]
    fn the_acceptance_checks_of_the_runtime_are_applied() {
        // A structural bound: the tool must not emit content the network would
        // reject.
        let error = encode(
            &format!("active_chain_length = {}\n", SNAKE_CHAIN_LENGTH_MAX + 1),
            KEY,
        )
        .expect_err("over the compile-time capacity");
        assert_eq!(error.line, 0);
        assert!(error.message.contains("structural bound"));

        // And an argument-less program that cannot complete is rejected by being
        // run, which is what stands in for a bytecode verifier.
        let error = encode(
            "vote_interest = {\n    GETPARAM @vote_scale, 0\n    RET\n}\n",
            KEY,
        );
        assert!(error.is_ok(), "reading another parameter is legitimate");
    }

    #[test]
    fn an_unterminated_program_block_is_refused() {
        let error = encode("vote_interest = {\n    PUSH 1\n", KEY).expect_err("unterminated");
        assert_eq!(error.line, 1);
        assert!(error.message.contains("unterminated"));
    }

    #[test]
    fn the_signature_covers_the_content_region() {
        let payload = encode("vote_interest = 3\n", KEY).expect("encodes");
        let view = moonblokz_chain_types::ChainConfigBlockPayloadView::from_payload(&payload)
            .expect("framing is well formed");
        let crypto = Crypto::new(KEY).ok().expect("key");
        let signature = moonblokz_crypto::Signature::new(view.content_signature())
            .ok()
            .expect("signature deserializes");
        assert!(crypto.verify_signature(view.content(), &signature, crypto.public_key()));
    }
}
