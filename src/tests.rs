//! Tests for the chain-configuration module.
//!
//! Deterministic inputs only: no wall-clock, no randomness. Payloads are framed
//! through the real `moonblokz-chain-types` builder wherever the framing is
//! meant to be well formed, and by hand where a malformed envelope is the point.

use core::cell::{Cell, RefCell};

use moonblokz_chain_types::{CONFIG_KEY_BYTECODE_FLAG, ChainConfigPayloadBuilder};
use moonblokz_crypto::{Crypto, CryptoTrait, PRIVATE_KEY_SIZE, SIGNATURE_SIZE};
use moonblokz_vm::opcode as op;

use super::*;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// An owned payload, so a test can keep one past the builder that framed it.
struct Payload {
    bytes: [u8; MAX_PAYLOAD_SIZE],
    len: usize,
}

impl Payload {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// One override entry to frame.
enum Entry<'a> {
    Literal(u8, &'a [u8]),
    Bytecode(u8, &'a [u8]),
}

fn test_crypto() -> Crypto {
    Crypto::new([1u8; PRIVATE_KEY_SIZE])
        .ok()
        .expect("test private key should be accepted")
}

/// Frames `entries` and appends a content signature — the shape a chain-config
/// block carries.
fn frame(entries: &[Entry<'_>]) -> Payload {
    let mut builder = ChainConfigPayloadBuilder::new();
    for entry in entries {
        let result = match entry {
            Entry::Literal(id, value) => builder.add_literal(*id, value),
            Entry::Bytecode(id, program) => builder.add_bytecode(*id, program),
        };
        result.ok().expect("fixture entry should frame");
    }
    let signed = builder.build_signed(&test_crypto());
    let mut bytes = [0u8; MAX_PAYLOAD_SIZE];
    bytes[..signed.len()].copy_from_slice(signed);
    Payload {
        bytes,
        len: signed.len(),
    }
}

/// Frames a declared count and a raw entry body, bypassing the builder so that
/// malformed envelopes can be exercised. The signature trailer is opaque to this
/// crate — FR7 verification is the blockchain's Tier-1 responsibility.
fn frame_raw(count: u16, body: &[u8]) -> Payload {
    let mut bytes = [0u8; MAX_PAYLOAD_SIZE];
    bytes[0..2].copy_from_slice(&count.to_le_bytes());
    bytes[2..2 + body.len()].copy_from_slice(body);
    Payload {
        bytes,
        len: 2 + body.len() + SIGNATURE_SIZE,
    }
}

fn loaded(entries: &[Entry<'_>]) -> ChainConfiguration<NoopConfigChangeSink> {
    let payload = frame(entries);
    let mut module = ChainConfiguration::new(NoopConfigChangeSink);
    module
        .load_tentative(payload.as_slice())
        .expect("fixture content should be accepted");
    module
}

// -- Programs --

/// `PUSH_U8 value; RET`
const fn push_u8_program(value: u8) -> [u8; 3] {
    [op::PUSH_U8, value, op::RET]
}

/// `PUSH_U16 value; RET`
fn push_u16_program(value: u16) -> [u8; 4] {
    let bytes = value.to_le_bytes();
    [op::PUSH_U16, bytes[0], bytes[1], op::RET]
}

/// `GETPARAM id, argc; RET`
const fn getparam_program(id: u8, argc: u8) -> [u8; 4] {
    [op::GETPARAM, id, argc, op::RET]
}

/// `JMP -3` — a program that never terminates, so it can only end on fuel.
const RUNAWAY_PROGRAM: [u8; 3] = [op::JMP, 0xFD, 0xFF];

/// A single unassigned opcode byte.
const UNDEFINED_OPCODE_PROGRAM: [u8; 1] = [0xC0];

// ---------------------------------------------------------------------------
// Defaults — the neutrality bar
// ---------------------------------------------------------------------------

#[test]
fn empty_override_set_resolves_every_default() {
    let module = loaded(&[]);
    let config = module
        .active_configuration()
        .expect("content is loaded, so a handle is available");

    // Blockchain parameters. These are the values the retired `FixedChainConfig`
    // returned, which is what makes the Story 5.8 migration behaviour-neutral.
    assert_eq!(config.inter_block_interval_ms(), 60_000);
    assert_eq!(config.grace_period_window_ms(), 30_000);
    assert_eq!(config.block_size_limit(), 2016);
    assert_eq!(config.max_utxo_outputs(), 255);
    assert_eq!(config.max_aggregated_signatures(), 50);
    assert_eq!(config.vote_scale().get(), 1000);
    assert_eq!(config.vote_interest(), 5);
    assert_eq!(config.parent_recovery_per_head_retry_interval_ms(), 120_000);
    assert_eq!(config.parent_recovery_min_emit_interval_ms(), 10_000);
    assert_eq!(config.required_support(), 3);
    assert_eq!(config.block_fill_threshold_percent(), 80);
    assert_eq!(config.active_chain_length(), 500);
    assert_eq!(config.mempool_replenishment_interval_ms(), 500_000);
    assert_eq!(config.custodian_fee(), 1);
    assert_eq!(config.registration_price(0), 100);
    assert_eq!(config.registration_price(10_000), 100);
    assert_eq!(config.tx_fee_per_byte_min(), 0);
    assert_eq!(config.tx_fee_per_byte_max(), 1000);
    assert_eq!(config.deviation_replay_insertion_delay_ms(), 300_000);
    assert_eq!(config.replay_block_reward(), 100);

    // Radio parameters, in their native units.
    assert_eq!(config.echo_request_minimal_interval(), 1440);
    assert_eq!(config.echo_messages_target_interval(), 100);
    assert_eq!(config.echo_gathering_timeout(), 10);
    assert_eq!(config.delay_between_tx_packets(), 200);
    assert_eq!(config.delay_between_tx_messages(), 20);
    assert_eq!(config.relay_position_delay(), 10);
    assert_eq!(config.scoring_matrix(), [255, 243, 65, 82, 143]);
    assert_eq!(config.retry_interval_for_missing_packets(), 60);
    assert_eq!(config.tx_maximum_random_delay(), 200);

    // VM parameters.
    assert_eq!(config.vm_fuel_limit(), 20_000);
}

#[test]
fn every_default_satisfies_its_own_bound() {
    // Absent parameters are not bound-checked at acceptance, so the defaults have
    // to be in range by construction.
    for spec in REGISTRY.iter() {
        check_bound(spec.id, spec.default)
            .expect("every code-baked default must satisfy its structural bound");
    }
}

#[test]
fn no_configuration_yields_no_handle() {
    let module = ChainConfiguration::new(NoopConfigChangeSink);
    assert!(module.active_configuration().is_none());
    assert!(module.tentative_content().is_none());
    assert!(module.durable_content().is_none());
    assert!(!module.is_durable_locked());
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

#[test]
fn literal_override_wins_over_the_default() {
    let module = loaded(&[Entry::Literal(
        parameter::INTER_BLOCK_INTERVAL_MS,
        &45_000u64.to_le_bytes(),
    )]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.inter_block_interval_ms(), 45_000);
    // An untouched parameter still resolves to its default.
    assert_eq!(config.grace_period_window_ms(), 30_000);
}

#[test]
fn bytecode_override_is_evaluated() {
    let program = push_u8_program(7);
    let module = loaded(&[Entry::Bytecode(parameter::VOTE_INTEREST, &program)]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.vote_interest(), 7);
}

#[test]
fn bytecode_reads_another_parameter_of_the_same_content() {
    // `grace_period_window_ms = inter_block_interval_ms / 2`, reading identifier 1
    // rather than restating its value.
    let program = [
        op::GETPARAM,
        parameter::INTER_BLOCK_INTERVAL_MS,
        0,
        op::PUSH_U8,
        2,
        op::DIV,
        op::RET,
    ];
    let module = loaded(&[
        Entry::Literal(parameter::INTER_BLOCK_INTERVAL_MS, &90_000u64.to_le_bytes()),
        Entry::Bytecode(parameter::GRACE_PERIOD_WINDOW_MS, &program),
    ]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.grace_period_window_ms(), 45_000);
}

#[test]
fn nested_resolution_sees_the_referenced_parameter_default() {
    // Identifier 1 is not overridden, so the nested resolution falls to its
    // code-baked default and the caller still gets a value.
    let program = [op::GETPARAM, parameter::INTER_BLOCK_INTERVAL_MS, 0, op::RET];
    let module = loaded(&[Entry::Bytecode(parameter::GRACE_PERIOD_WINDOW_MS, &program)]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.grace_period_window_ms(), 60_000);
}

#[test]
fn a_declared_argument_count_that_contradicts_the_registry_is_declined() {
    // `GETPARAM 1, 1` declares one argument for an argument-less parameter. The
    // host owns the registry, so the host is where the disagreement is caught;
    // it reaches the program as a failed call and the tier falls through.
    let program = [
        op::PUSH_U8,
        0,
        op::GETPARAM,
        parameter::INTER_BLOCK_INTERVAL_MS,
        1,
        op::RET,
    ];
    // Argument-taking so that acceptance does not evaluate it: the point here is
    // the runtime fallback, not the acceptance rejection.
    let module = loaded(&[Entry::Bytecode(parameter::REGISTRATION_PRICE, &program)]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.registration_price(5), 100);
}

#[test]
fn an_unallocated_identifier_is_declined_at_the_host_seam() {
    let program = getparam_program(120, 0);
    let module = loaded(&[Entry::Bytecode(parameter::REGISTRATION_PRICE, &program)]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.registration_price(1), 100);
}

#[test]
fn an_argument_taking_program_that_traps_falls_back_to_the_default() {
    // `ARG 3` with arity 1 is an operand index out of range: a runtime condition
    // no acceptance-time check can reach, which is exactly why an argument-taking
    // parameter may not carry a structural bound.
    let program = [op::ARG, 3, op::RET];
    let module = loaded(&[Entry::Bytecode(parameter::REGISTRATION_PRICE, &program)]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.registration_price(7), 100);
}

#[test]
fn an_argument_taking_program_receives_its_argument() {
    // `registration_price(n) = 5 · n`
    let program = [op::ARG, 0, op::PUSH_U8, 5, op::MUL, op::RET];
    let module = loaded(&[Entry::Bytecode(parameter::REGISTRATION_PRICE, &program)]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.registration_price(0), 0);
    assert_eq!(config.registration_price(200), 1000);
}

#[test]
fn a_narrower_accessor_saturates() {
    let program = push_u16_program(300);
    let module = loaded(&[Entry::Bytecode(parameter::VOTE_INTEREST, &program)]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.vote_interest(), u8::MAX);
}

#[test]
fn the_fuel_limit_override_bounds_evaluation() {
    // One unit buys nothing: the program cannot complete, so the tier fails and
    // the default stands. The limit is chain configuration precisely because it
    // decides which programs complete, and therefore which values a node reads.
    let program = [op::PUSH_U8, 9, op::RET];
    let module = loaded(&[
        Entry::Literal(parameter::VM_FUEL_LIMIT, &1u32.to_le_bytes()),
        Entry::Bytecode(parameter::REGISTRATION_PRICE, &program),
    ]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.vm_fuel_limit(), 1);
    assert_eq!(config.registration_price(0), 100);
}

#[test]
fn each_accessor_invocation_starts_from_a_fresh_budget() {
    // A program that costs most of a small budget still resolves on every call:
    // budgets are per invocation, not drawn from a running total.
    let program = [op::PUSH_U8, 1, op::PUSH_U8, 2, op::ADD, op::RET];
    let module = loaded(&[
        Entry::Literal(parameter::VM_FUEL_LIMIT, &4u32.to_le_bytes()),
        Entry::Bytecode(parameter::REGISTRATION_PRICE, &program),
    ]);
    let config = module.active_configuration().expect("handle");

    for _ in 0..8 {
        assert_eq!(config.registration_price(0), 3);
    }
}

// ---------------------------------------------------------------------------
// Registry conformance
// ---------------------------------------------------------------------------

#[test]
fn an_unallocated_identifier_is_rejected_with_its_key_byte() {
    let payload = frame(&[Entry::Literal(120, &[1])]);
    let error = accept_content(payload.as_slice()).expect_err("identifier 120 is unallocated");
    assert!(matches!(error, ChainConfigError::UnknownParameter(120)));

    // The bytecode form carries the flag bit into the log record, so an operator
    // sees the byte as written.
    let program = push_u8_program(1);
    let payload = frame(&[Entry::Bytecode(120, &program)]);
    let error = accept_content(payload.as_slice()).expect_err("identifier 120 is unallocated");
    assert!(matches!(
        error,
        ChainConfigError::UnknownParameter(byte) if byte == 120 | CONFIG_KEY_BYTECODE_FLAG
    ));
}

#[test]
fn a_width_mismatched_literal_is_rejected() {
    // Four bytes under an eight-byte parameter.
    let payload = frame(&[Entry::Literal(
        parameter::INTER_BLOCK_INTERVAL_MS,
        &1u32.to_le_bytes(),
    )]);
    let error = accept_content(payload.as_slice()).expect_err("width must match exactly");
    assert!(matches!(
        error,
        ChainConfigError::ValueWidthMismatch(parameter::INTER_BLOCK_INTERVAL_MS)
    ));
}

#[test]
fn bytecode_under_a_literal_only_parameter_is_rejected() {
    let program = push_u8_program(4);
    for id in [
        parameter::MAX_BLOCK_UTXO_OUTPUT,
        parameter::MAX_AGGREGATED_SIGNATURES,
        parameter::VOTE_SCALE,
        parameter::REQUIRED_SUPPORT,
        parameter::ACTIVE_CHAIN_LENGTH,
        parameter::SCORING_MATRIX,
        parameter::VM_FUEL_LIMIT,
    ] {
        let payload = frame(&[Entry::Bytecode(id, &program)]);
        let error = accept_content(payload.as_slice())
            .expect_err("a literal-only parameter refuses a program");
        assert!(
            matches!(error, ChainConfigError::BytecodeNotPermitted(rejected) if rejected == id)
        );
    }
}

#[test]
fn a_duplicate_identifier_is_malformed_framing() {
    let payload = frame_raw(
        2,
        &[
            parameter::VOTE_INTEREST,
            1,
            5,
            parameter::VOTE_INTEREST | CONFIG_KEY_BYTECODE_FLAG,
            1,
            5,
        ],
    );
    let error = accept_content(payload.as_slice()).expect_err("a duplicate key is malformed");
    assert!(matches!(error, ChainConfigError::MalformedContent));
}

#[test]
fn the_unusable_key_bytes_are_malformed_framing() {
    for key_byte in [0x00u8, 0x7F, 0x80, 0xFF] {
        let payload = frame_raw(1, &[key_byte, 1, 5]);
        let error = accept_content(payload.as_slice()).expect_err("key byte must be usable");
        assert!(matches!(error, ChainConfigError::MalformedContent));
    }
}

#[test]
fn a_payload_over_the_retention_buffer_is_refused() {
    let mut module = ChainConfiguration::new(NoopConfigChangeSink);
    let oversized = [0u8; MAX_PAYLOAD_SIZE + 1];
    let error = module
        .load_tentative(&oversized)
        .expect_err("the retention buffer is fixed");
    assert!(matches!(error, ChainConfigError::MalformedContent));
    assert!(module.active_configuration().is_none());
}

// ---------------------------------------------------------------------------
// Structural bounds
// ---------------------------------------------------------------------------

#[test]
fn required_support_is_bounded_at_both_ends() {
    let accepted = frame(&[Entry::Literal(
        parameter::REQUIRED_SUPPORT,
        &[MAX_AGGREGATED_SIGNATURES as u8],
    )]);
    assert!(accept_content(accepted.as_slice()).is_ok());

    let over = frame(&[Entry::Literal(
        parameter::REQUIRED_SUPPORT,
        &[MAX_AGGREGATED_SIGNATURES as u8 + 1],
    )]);
    assert!(matches!(
        accept_content(over.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::REQUIRED_SUPPORT
        ))
    ));

    let at_one = frame(&[Entry::Literal(parameter::REQUIRED_SUPPORT, &[1])]);
    assert!(accept_content(at_one.as_slice()).is_ok());

    let zero = frame(&[Entry::Literal(parameter::REQUIRED_SUPPORT, &[0])]);
    assert!(matches!(
        accept_content(zero.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::REQUIRED_SUPPORT
        ))
    ));
}

#[test]
fn vote_scale_may_not_be_zero() {
    let accepted = frame(&[Entry::Literal(parameter::VOTE_SCALE, &1u16.to_le_bytes())]);
    assert!(accept_content(accepted.as_slice()).is_ok());

    let zero = frame(&[Entry::Literal(parameter::VOTE_SCALE, &0u16.to_le_bytes())]);
    assert!(matches!(
        accept_content(zero.as_slice()),
        Err(ChainConfigError::BoundViolation(parameter::VOTE_SCALE))
    ));
}

#[test]
fn block_size_limit_is_bounded_by_the_block_buffer() {
    let at_bound = frame(&[Entry::Literal(
        parameter::BLOCK_SIZE_LIMIT,
        &(MAX_BLOCK_SIZE as u16).to_le_bytes(),
    )]);
    assert!(accept_content(at_bound.as_slice()).is_ok());

    let over = frame(&[Entry::Literal(
        parameter::BLOCK_SIZE_LIMIT,
        &(MAX_BLOCK_SIZE as u16 + 1).to_le_bytes(),
    )]);
    assert!(matches!(
        accept_content(over.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::BLOCK_SIZE_LIMIT
        ))
    ));
}

#[test]
fn active_chain_length_is_bounded_by_the_compile_time_capacity() {
    let at_bound = frame(&[Entry::Literal(
        parameter::ACTIVE_CHAIN_LENGTH,
        &SNAKE_CHAIN_LENGTH_MAX.to_le_bytes(),
    )]);
    assert!(accept_content(at_bound.as_slice()).is_ok());

    let over = frame(&[Entry::Literal(
        parameter::ACTIVE_CHAIN_LENGTH,
        &(SNAKE_CHAIN_LENGTH_MAX + 1).to_le_bytes(),
    )]);
    assert!(matches!(
        accept_content(over.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::ACTIVE_CHAIN_LENGTH
        ))
    ));
}

#[test]
fn max_block_utxo_output_is_bounded_by_the_spent_bit_width() {
    // The bound is `≤ UTXO_UNSPENT_BITS`, and the parameter is one byte wide, so
    // the widest legal literal is in range on this build...
    let at_width_max = frame(&[Entry::Literal(parameter::MAX_BLOCK_UTXO_OUTPUT, &[255])]);
    assert!(accept_content(at_width_max.as_slice()).is_ok());
    assert!(check_bound(parameter::MAX_BLOCK_UTXO_OUTPUT, UTXO_UNSPENT_BITS as u64).is_ok());

    // ... a value above it is rejected twice over: by the bound, and — because a
    // wider value needs a wider literal — by the exact-width rule first.
    assert!(matches!(
        check_bound(
            parameter::MAX_BLOCK_UTXO_OUTPUT,
            UTXO_UNSPENT_BITS as u64 + 1
        ),
        Err(ChainConfigError::BoundViolation(
            parameter::MAX_BLOCK_UTXO_OUTPUT
        ))
    ));
    let too_wide = frame(&[Entry::Literal(
        parameter::MAX_BLOCK_UTXO_OUTPUT,
        &(UTXO_UNSPENT_BITS + 1).to_le_bytes(),
    )]);
    assert!(matches!(
        accept_content(too_wide.as_slice()),
        Err(ChainConfigError::ValueWidthMismatch(
            parameter::MAX_BLOCK_UTXO_OUTPUT
        ))
    ));
}

#[test]
fn an_argument_less_bytecode_override_is_bound_checked_at_acceptance() {
    let over = push_u16_program(MAX_BLOCK_SIZE as u16 + 1);
    let payload = frame(&[Entry::Bytecode(parameter::BLOCK_SIZE_LIMIT, &over)]);
    assert!(matches!(
        accept_content(payload.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::BLOCK_SIZE_LIMIT
        ))
    ));

    let within = push_u16_program(1024);
    let payload = frame(&[Entry::Bytecode(parameter::BLOCK_SIZE_LIMIT, &within)]);
    assert!(accept_content(payload.as_slice()).is_ok());
}

#[test]
fn an_argument_less_program_that_traps_rejects_the_content() {
    let payload = frame(&[Entry::Bytecode(
        parameter::VOTE_INTEREST,
        &UNDEFINED_OPCODE_PROGRAM,
    )]);
    assert!(matches!(
        accept_content(payload.as_slice()),
        Err(ChainConfigError::BytecodeEvaluationFailed(
            parameter::VOTE_INTEREST
        ))
    ));
}

#[test]
fn an_argument_less_program_that_runs_out_of_fuel_rejects_the_content() {
    let payload = frame(&[Entry::Bytecode(parameter::VOTE_INTEREST, &RUNAWAY_PROGRAM)]);
    assert!(matches!(
        accept_content(payload.as_slice()),
        Err(ChainConfigError::BytecodeEvaluationFailed(
            parameter::VOTE_INTEREST
        ))
    ));
}

#[test]
fn an_argument_taking_program_is_not_evaluated_at_acceptance() {
    // It cannot be: no acceptance-time check covers every argument value. A
    // program that would trap on some argument is accepted here and falls back at
    // runtime, deterministically and identically on every node.
    let payload = frame(&[Entry::Bytecode(
        parameter::REGISTRATION_PRICE,
        &UNDEFINED_OPCODE_PROGRAM,
    )]);
    assert!(accept_content(payload.as_slice()).is_ok());
}

#[test]
fn a_rejected_content_leaves_the_previous_state_untouched() {
    let good = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[9])]);
    let bad = frame(&[Entry::Literal(parameter::REQUIRED_SUPPORT, &[0])]);

    let mut module = ChainConfiguration::new(NoopConfigChangeSink);
    module.load_tentative(good.as_slice()).expect("accepted");
    assert!(module.load_tentative(bad.as_slice()).is_err());

    let config = module.active_configuration().expect("handle");
    assert_eq!(config.vote_interest(), 9);
}

// ---------------------------------------------------------------------------
// FR8 commitment state
// ---------------------------------------------------------------------------

#[test]
fn tentative_load_exposes_tentative_content_only() {
    let payload = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[6])]);
    let mut module = ChainConfiguration::new(NoopConfigChangeSink);
    module.load_tentative(payload.as_slice()).expect("accepted");

    let content_len = payload.len - SIGNATURE_SIZE;
    assert_eq!(
        module.tentative_content(),
        Some(&payload.as_slice()[..content_len])
    );
    assert!(module.durable_content().is_none());
    assert!(!module.is_durable_locked());
    assert_eq!(
        module.active_configuration().expect("handle").commitment(),
        Commitment::Tentative
    );
}

#[test]
fn promotion_flips_the_flag_over_the_same_bytes() {
    let payload = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[6])]);
    let mut module = ChainConfiguration::new(NoopConfigChangeSink);
    module.load_tentative(payload.as_slice()).expect("accepted");
    let before = module.tentative_content().expect("tentative").len();

    module.promote_durable().expect("first promotion");

    assert!(module.is_durable_locked());
    assert!(module.tentative_content().is_none());
    let after = module.durable_content().expect("durable");
    assert_eq!(after.len(), before);
    assert_eq!(
        module.active_configuration().expect("handle").commitment(),
        Commitment::Durable
    );
    assert_eq!(
        module
            .active_configuration()
            .expect("handle")
            .vote_interest(),
        6
    );
}

#[test]
fn a_second_promotion_is_refused() {
    let payload = frame(&[]);
    let mut module = ChainConfiguration::new(NoopConfigChangeSink);
    module.load_tentative(payload.as_slice()).expect("accepted");
    module.promote_durable().expect("first promotion");

    assert!(matches!(
        module.promote_durable(),
        Err(ChainConfigError::DurableLocked)
    ));
    assert!(module.is_durable_locked());
}

#[test]
fn promotion_without_content_is_refused() {
    let mut module = ChainConfiguration::new(NoopConfigChangeSink);
    assert!(matches!(
        module.promote_durable(),
        Err(ChainConfigError::NotLoaded)
    ));
}

#[test]
fn a_load_after_the_durable_lock_is_refused() {
    let first = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[6])]);
    let second = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[7])]);

    let mut module = ChainConfiguration::new(NoopConfigChangeSink);
    module.load_durable(first.as_slice()).expect("accepted");

    assert!(matches!(
        module.load_tentative(second.as_slice()),
        Err(ChainConfigError::DurableLocked)
    ));
    assert!(matches!(
        module.load_durable(second.as_slice()),
        Err(ChainConfigError::DurableLocked)
    ));
    // The durable configuration is never destroyed or rewritten.
    assert_eq!(
        module
            .active_configuration()
            .expect("handle")
            .vote_interest(),
        6
    );
}

#[test]
fn discard_returns_the_module_to_absent() {
    let payload = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[6])]);
    let mut module = ChainConfiguration::new(NoopConfigChangeSink);
    module.load_tentative(payload.as_slice()).expect("accepted");

    module.discard_tentative();

    assert!(module.active_configuration().is_none());
    assert!(module.tentative_content().is_none());

    // ... and a new tentative can then be adopted.
    let replacement = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[8])]);
    module
        .load_tentative(replacement.as_slice())
        .expect("accepted");
    assert_eq!(
        module
            .active_configuration()
            .expect("handle")
            .vote_interest(),
        8
    );
}

#[test]
fn discard_never_drops_a_durable_configuration() {
    let payload = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[6])]);
    let mut module = ChainConfiguration::new(NoopConfigChangeSink);
    module.load_durable(payload.as_slice()).expect("accepted");

    module.discard_tentative();

    assert!(module.is_durable_locked());
    assert_eq!(
        module
            .active_configuration()
            .expect("handle")
            .vote_interest(),
        6
    );
}

// ---------------------------------------------------------------------------
// Change notification
// ---------------------------------------------------------------------------

/// Records what the module reported, so a test can assert the transitions rather
/// than the absence of a panic.
struct RecordingSink {
    calls: Cell<usize>,
    observed: RefCell<[Option<(Commitment, u8)>; 4]>,
}

impl RecordingSink {
    const fn new() -> Self {
        Self {
            calls: Cell::new(0),
            observed: RefCell::new([None; 4]),
        }
    }
}

impl ConfigChangeSink for RecordingSink {
    fn on_configuration_changed(&self, config: &ActiveConfig<'_>) {
        let index = self.calls.get();
        self.calls.set(index + 1);
        if index < 4 {
            // Reading through the handle is the point: the sink is handed the
            // accessor surface, not a copy of the bytes.
            self.observed.borrow_mut()[index] = Some((config.commitment(), config.vote_interest()));
        }
    }
}

#[test]
fn the_sink_observes_exactly_the_state_transitions() {
    let first = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[1])]);
    let replacement = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[2])]);
    let rejected = frame(&[Entry::Literal(parameter::REQUIRED_SUPPORT, &[0])]);

    let mut module = ChainConfiguration::new(RecordingSink::new());

    module.load_tentative(first.as_slice()).expect("accepted");
    // The FR8 mismatch path: a replacement tentative is a transition too.
    module
        .load_tentative(replacement.as_slice())
        .expect("accepted");
    // A refused content is not a transition.
    assert!(module.load_tentative(rejected.as_slice()).is_err());
    module.promote_durable().expect("promotion");
    // Neither is a refused promotion.
    assert!(module.promote_durable().is_err());

    let sink = &module.sink;
    assert_eq!(sink.calls.get(), 3);
    assert_eq!(
        *sink.observed.borrow(),
        [
            Some((Commitment::Tentative, 1)),
            Some((Commitment::Tentative, 2)),
            Some((Commitment::Durable, 2)),
            None,
        ]
    );
}

#[test]
fn discard_is_not_reported() {
    // There is no configuration to hand the sink after a discard, and the
    // adoption of the next tentative is the transition consumers act on.
    let payload = frame(&[Entry::Literal(parameter::VOTE_INTEREST, &[1])]);
    let mut module = ChainConfiguration::new(RecordingSink::new());
    module.load_tentative(payload.as_slice()).expect("accepted");
    module.discard_tentative();

    assert_eq!(module.sink.calls.get(), 1);
}
