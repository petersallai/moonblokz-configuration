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

/// `PUSH_U8 41; RET` — a `'static` program, so it can stand in as a code-baked
/// tier-2 default.
const PUSH_41_PROGRAM: [u8; 3] = push_u8_program(41);

/// `ARG 0; PUSH_U8 2; MUL; RET` — doubles its argument.
const DOUBLE_ARG_PROGRAM: [u8; 6] = [op::ARG, 0, op::PUSH_U8, 2, op::MUL, op::RET];

/// `ARG 3; RET` — an operand index above the arity, so it traps at runtime while
/// acceptance cannot reach it.
const ARG_OUT_OF_RANGE_PROGRAM: [u8; 3] = [op::ARG, 3, op::RET];

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
    // Absent parameters are not bound-checked at acceptance, so both code-baked
    // tiers have to be in range by construction. A literal default and its
    // fallback are the same value; a program default is checked through its
    // fallback, which is the value a failing program lands on.
    for spec in REGISTRY.iter() {
        check_bound(spec.id, spec.fallback)
            .expect("every code-baked fallback literal must satisfy its structural bound");
        if let DefaultValue::Literal(default) = spec.default {
            check_bound(spec.id, default)
                .expect("every code-baked default must satisfy its structural bound");
        }
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
        &45_000u32.to_le_bytes(),
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
        Entry::Literal(parameter::INTER_BLOCK_INTERVAL_MS, &90_000u32.to_le_bytes()),
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
// Tier 2 — the code-baked default as a program
// ---------------------------------------------------------------------------
//
// No parameter in the registry carries a program default, so these exercise the
// resolution mechanism through a synthetic spec rather than through content. That
// is the point: the tier has to work before a registry entry relies on it.

#[test]
fn a_program_default_resolves_as_tier_two() {
    let module = loaded(&[]);
    let config = module.active_configuration().expect("handle");
    let spec = spec_of_program(parameter::CUSTODIAN_FEE, 8, 0, true, &PUSH_41_PROGRAM, 7);

    let mut fuel = Fuel::new(config.fuel_limit());
    assert_eq!(config.resolve_with(&spec, &[], &mut fuel), 41);
}

#[test]
fn a_program_default_that_fails_falls_through_to_the_fallback_literal() {
    let module = loaded(&[]);
    let config = module.active_configuration().expect("handle");
    let spec = spec_of_program(
        parameter::CUSTODIAN_FEE,
        8,
        0,
        true,
        &UNDEFINED_OPCODE_PROGRAM,
        7,
    );

    let mut fuel = Fuel::new(config.fuel_limit());
    assert_eq!(config.resolve_with(&spec, &[], &mut fuel), 7);
}

#[test]
fn tier_two_starts_from_a_fresh_budget_after_tier_one_exhausts_one() {
    // The override traps at runtime — an operand index above the arity, which
    // acceptance cannot reach because the parameter takes an argument — and the
    // incoming budget is empty, which is what an exhausted tier-1 evaluation
    // leaves behind. Tier 2 must still run, or every fuel-caused failure would
    // skip it and the tier would be dead code in exactly the case it exists for.
    let module = loaded(&[Entry::Bytecode(
        parameter::REGISTRATION_PRICE,
        &ARG_OUT_OF_RANGE_PROGRAM,
    )]);
    let config = module.active_configuration().expect("handle");
    let spec = spec_of_program(
        parameter::REGISTRATION_PRICE,
        8,
        1,
        true,
        &DOUBLE_ARG_PROGRAM,
        7,
    );

    let mut exhausted = Fuel::new(0);
    // The argument reaches tier 2 with the same semantics the accessor has.
    assert_eq!(config.resolve_with(&spec, &[21], &mut exhausted), 42);
}

// ---------------------------------------------------------------------------
// Nesting and cycles
// ---------------------------------------------------------------------------

#[test]
fn a_self_referential_program_resolves_to_the_default_it_cannot_reach() {
    // `grace_period_window_ms = GETPARAM grace_period_window_ms`. The host
    // re-enters the VM, and the depth counter travels in `Fuel`, so the recursion
    // stops at the fixed nesting limit rather than on the native stack. The
    // innermost `GETPARAM` traps, that tier fails, and the sub-evaluation returns
    // the code-baked default — so the outer program *completes*, carrying the
    // default outward. Acceptance therefore accepts the content: a cycle is a
    // runtime condition with the ordinary fallback outcome, not invalidity.
    let program = getparam_program(parameter::GRACE_PERIOD_WINDOW_MS, 0);
    let module = loaded(&[Entry::Bytecode(parameter::GRACE_PERIOD_WINDOW_MS, &program)]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.grace_period_window_ms(), 30_000);
    // Deterministic, which is what makes it safe: the depth limit and the fuel
    // budget are both chain-fixed, so every node reaches the same value.
    assert_eq!(config.grace_period_window_ms(), 30_000);
}

#[test]
fn a_two_parameter_cycle_terminates_the_same_way() {
    let first = getparam_program(parameter::GRACE_PERIOD_WINDOW_MS, 0);
    let second = getparam_program(parameter::INTER_BLOCK_INTERVAL_MS, 0);
    let module = loaded(&[
        Entry::Bytecode(parameter::INTER_BLOCK_INTERVAL_MS, &first),
        Entry::Bytecode(parameter::GRACE_PERIOD_WINDOW_MS, &second),
    ]);
    let config = module.active_configuration().expect("handle");

    // Each side bottoms out on the other's default once the nesting limit bites.
    assert_eq!(config.inter_block_interval_ms(), 30_000);
    assert_eq!(config.grace_period_window_ms(), 60_000);
}

#[test]
fn a_cycle_through_an_argument_taking_parameter_terminates_at_runtime() {
    // Acceptance does not evaluate an argument-taking program, so this cycle is
    // reachable at resolution time — the case that would be a stack overflow if
    // the nesting depth did not survive the host re-entry. It resolves to the
    // default instead.
    let program = [
        op::ARG,
        0,
        op::GETPARAM,
        parameter::REGISTRATION_PRICE,
        1,
        op::RET,
    ];
    let module = loaded(&[Entry::Bytecode(parameter::REGISTRATION_PRICE, &program)]);
    let config = module.active_configuration().expect("handle");

    assert_eq!(config.registration_price(3), 100);
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
fn every_duration_is_four_bytes_wide() {
    // The declared widths are permanent wire format, so the rule is pinned by a
    // test rather than only by the table: every millisecond duration takes a
    // `u32`, and the eight-byte form they used to take is now malformed.
    for id in [
        parameter::INTER_BLOCK_INTERVAL_MS,
        parameter::GRACE_PERIOD_WINDOW_MS,
        parameter::PARENT_RECOVERY_PER_HEAD_RETRY_INTERVAL_MS,
        parameter::PARENT_RECOVERY_MIN_EMIT_INTERVAL_MS,
        parameter::MEMPOOL_REPLENISHMENT_INTERVAL_MS,
        parameter::DEVIATION_REPLAY_INSERTION_DELAY_MS,
    ] {
        let four = frame(&[Entry::Literal(id, &900_000u32.to_le_bytes())]);
        assert!(
            accept_content(four.as_slice()).is_ok(),
            "identifier {id} should accept a four-byte literal"
        );

        let eight = frame(&[Entry::Literal(id, &900_000u64.to_le_bytes())]);
        assert!(
            matches!(
                accept_content(eight.as_slice()),
                Err(ChainConfigError::ValueWidthMismatch(rejected)) if rejected == id
            ),
            "identifier {id} should refuse an eight-byte literal"
        );
    }

    // The value-typed parameters are untouched: only durations narrowed.
    let module = loaded(&[Entry::Literal(
        parameter::MEMPOOL_REPLENISHMENT_INTERVAL_MS,
        &900_000u32.to_le_bytes(),
    )]);
    assert_eq!(
        module
            .active_configuration()
            .expect("handle")
            .mempool_replenishment_interval_ms(),
        900_000
    );
}

#[test]
fn a_width_mismatched_literal_is_rejected() {
    // Four bytes under an eight-byte parameter: `custodian_fee` is a value, not a
    // duration, so it stays `u64`.
    let payload = frame(&[Entry::Literal(
        parameter::CUSTODIAN_FEE,
        &1u32.to_le_bytes(),
    )]);
    let error = accept_content(payload.as_slice()).expect_err("width must match exactly");
    assert!(matches!(
        error,
        ChainConfigError::ValueWidthMismatch(parameter::CUSTODIAN_FEE)
    ));

    // And eight bytes under a four-byte one: every duration is `u32`
    // milliseconds, so the wide form its accessor used to take is malformed.
    let payload = frame(&[Entry::Literal(
        parameter::INTER_BLOCK_INTERVAL_MS,
        &1u64.to_le_bytes(),
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

    // A limit that cannot admit a header admits no block at all, and every
    // remaining-capacity computation against it underflows.
    let above_header = frame(&[Entry::Literal(
        parameter::BLOCK_SIZE_LIMIT,
        &(HEADER_SIZE as u16 + 1).to_le_bytes(),
    )]);
    assert!(accept_content(above_header.as_slice()).is_ok());

    let at_header = frame(&[Entry::Literal(
        parameter::BLOCK_SIZE_LIMIT,
        &(HEADER_SIZE as u16).to_le_bytes(),
    )]);
    assert!(matches!(
        accept_content(at_header.as_slice()),
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

    // A window has to hold at least one block.
    let at_one = frame(&[Entry::Literal(
        parameter::ACTIVE_CHAIN_LENGTH,
        &1u16.to_le_bytes(),
    )]);
    assert!(accept_content(at_one.as_slice()).is_ok());

    let zero = frame(&[Entry::Literal(
        parameter::ACTIVE_CHAIN_LENGTH,
        &0u16.to_le_bytes(),
    )]);
    assert!(matches!(
        accept_content(zero.as_slice()),
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

    // At zero no transaction output could ever be included in a block.
    let zero = frame(&[Entry::Literal(parameter::MAX_BLOCK_UTXO_OUTPUT, &[0])]);
    assert!(matches!(
        accept_content(zero.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::MAX_BLOCK_UTXO_OUTPUT
        ))
    ));
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
fn max_aggregated_signatures_is_bounded_by_the_backend_ceiling() {
    // The chain states how many signatures an approval-evidence block may carry;
    // this build states how many it can aggregate and verify.
    let at_bound = frame(&[Entry::Literal(
        parameter::MAX_AGGREGATED_SIGNATURES,
        &[MAX_AGGREGATED_SIGNATURES as u8],
    )]);
    assert!(accept_content(at_bound.as_slice()).is_ok());

    let over = frame(&[Entry::Literal(
        parameter::MAX_AGGREGATED_SIGNATURES,
        &[MAX_AGGREGATED_SIGNATURES as u8 + 1],
    )]);
    assert!(matches!(
        accept_content(over.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::MAX_AGGREGATED_SIGNATURES
        ))
    ));

    let zero = frame(&[Entry::Literal(parameter::MAX_AGGREGATED_SIGNATURES, &[0])]);
    assert!(matches!(
        accept_content(zero.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::MAX_AGGREGATED_SIGNATURES
        ))
    ));
}

#[test]
fn block_fill_threshold_is_a_percentage() {
    let at_bound = frame(&[Entry::Literal(
        parameter::BLOCK_FILL_THRESHOLD_PERCENT,
        &[100],
    )]);
    assert!(accept_content(at_bound.as_slice()).is_ok());

    let over = frame(&[Entry::Literal(
        parameter::BLOCK_FILL_THRESHOLD_PERCENT,
        &[101],
    )]);
    assert!(matches!(
        accept_content(over.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::BLOCK_FILL_THRESHOLD_PERCENT
        ))
    ));
}

#[test]
fn the_fuel_limit_is_bounded_at_both_ends() {
    // The ceiling *is* the default, which makes the budget a downward-only knob: a
    // chain can buy itself shorter evaluations, never longer ones.
    assert_eq!(
        u64::from(VM_FUEL_LIMIT_MAX),
        spec(parameter::VM_FUEL_LIMIT).fallback
    );

    let at_bound = frame(&[Entry::Literal(
        parameter::VM_FUEL_LIMIT,
        &VM_FUEL_LIMIT_MAX.to_le_bytes(),
    )]);
    assert!(accept_content(at_bound.as_slice()).is_ok());

    // Unbounded above, one content could hold the core for as long as it asked —
    // acceptance pays the limit once per argument-less program.
    let over = frame(&[Entry::Literal(
        parameter::VM_FUEL_LIMIT,
        &(VM_FUEL_LIMIT_MAX + 1).to_le_bytes(),
    )]);
    assert!(matches!(
        accept_content(over.as_slice()),
        Err(ChainConfigError::BoundViolation(parameter::VM_FUEL_LIMIT))
    ));

    // At zero every program silently resolves to its default, with no diagnostic
    // anywhere.
    let zero = frame(&[Entry::Literal(
        parameter::VM_FUEL_LIMIT,
        &0u32.to_le_bytes(),
    )]);
    assert!(matches!(
        accept_content(zero.as_slice()),
        Err(ChainConfigError::BoundViolation(parameter::VM_FUEL_LIMIT))
    ));
}

#[test]
fn an_over_budget_fuel_limit_is_refused_whatever_else_the_content_holds() {
    // Acceptance no longer spends the budget, so there is no ordering hazard left
    // to guard -- but the bound still matters, because *resolution* spends it on
    // every accessor call that reaches a program. Framed alongside a runaway
    // program, which is now accepted on its own.
    let payload = frame(&[
        Entry::Bytecode(parameter::VOTE_INTEREST, &RUNAWAY_PROGRAM),
        Entry::Literal(parameter::VM_FUEL_LIMIT, &u32::MAX.to_le_bytes()),
    ]);
    assert!(matches!(
        accept_content(payload.as_slice()),
        Err(ChainConfigError::BoundViolation(parameter::VM_FUEL_LIMIT))
    ));
}

#[test]
fn the_transaction_fee_range_may_not_be_inverted() {
    // The one invariant that spans two parameters, so it cannot live in a
    // per-parameter check.
    let equal = frame(&[
        Entry::Literal(parameter::TX_FEE_PER_BYTE_MIN, &7u64.to_le_bytes()),
        Entry::Literal(parameter::TX_FEE_PER_BYTE_MAX, &7u64.to_le_bytes()),
    ]);
    assert!(accept_content(equal.as_slice()).is_ok());

    let inverted = frame(&[
        Entry::Literal(parameter::TX_FEE_PER_BYTE_MIN, &8u64.to_le_bytes()),
        Entry::Literal(parameter::TX_FEE_PER_BYTE_MAX, &7u64.to_le_bytes()),
    ]);
    assert!(matches!(
        accept_content(inverted.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::TX_FEE_PER_BYTE_MIN
        ))
    ));

    // An omitted parameter contributes its default, which is the value the chain
    // will resolve for it: a minimum above the default maximum is still inverted.
    let over_default_max = frame(&[Entry::Literal(
        parameter::TX_FEE_PER_BYTE_MIN,
        &2000u64.to_le_bytes(),
    )]);
    assert!(matches!(
        accept_content(over_default_max.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::TX_FEE_PER_BYTE_MIN
        ))
    ));
}

#[test]
fn a_program_under_a_bounded_parameter_is_not_bound_checked() {
    // The consequence of dropping acceptance-time evaluation, stated as a test so
    // it is a decision rather than a surprise: a program may drive a bounded
    // parameter out of range. It is confined to the two bounded parameters that
    // admit a program at all, and to a *weaker rule* the whole chain applies
    // alike -- never to a value this node cannot represent, because every
    // representation-critical bound sits on a literal-only parameter.
    let over = push_u16_program(MAX_BLOCK_SIZE as u16 + 1);
    let payload = frame(&[Entry::Bytecode(parameter::BLOCK_SIZE_LIMIT, &over)]);
    assert!(accept_content(payload.as_slice()).is_ok());

    let module = loaded(&[Entry::Bytecode(parameter::BLOCK_SIZE_LIMIT, &over)]);
    assert_eq!(
        module
            .active_configuration()
            .expect("handle")
            .block_size_limit(),
        MAX_BLOCK_SIZE as u16 + 1
    );

    // The literal form of the same parameter is still checked.
    let literal = frame(&[Entry::Literal(
        parameter::BLOCK_SIZE_LIMIT,
        &(MAX_BLOCK_SIZE as u16 + 1).to_le_bytes(),
    )]);
    assert!(matches!(
        accept_content(literal.as_slice()),
        Err(ChainConfigError::BoundViolation(
            parameter::BLOCK_SIZE_LIMIT
        ))
    ));
}

#[test]
fn a_program_that_traps_is_accepted_and_falls_back_at_resolution() {
    // Acceptance does not run programs: a partial check in front of a total
    // mechanism buys nothing. An undefined opcode is a trap, the tier fails, and
    // resolution falls through to the code-baked default -- deterministically, so
    // every node reaches the same value.
    let payload = frame(&[Entry::Bytecode(
        parameter::VOTE_INTEREST,
        &UNDEFINED_OPCODE_PROGRAM,
    )]);
    assert!(accept_content(payload.as_slice()).is_ok());

    let module = loaded(&[Entry::Bytecode(
        parameter::VOTE_INTEREST,
        &UNDEFINED_OPCODE_PROGRAM,
    )]);
    let config = module.active_configuration().expect("handle");
    assert_eq!(config.vote_interest(), 5);
    // Stable across calls: the failure is a property of the program, not of state.
    assert_eq!(config.vote_interest(), 5);
}

#[test]
fn a_program_that_runs_out_of_fuel_is_accepted_and_falls_back() {
    let payload = frame(&[Entry::Bytecode(parameter::VOTE_INTEREST, &RUNAWAY_PROGRAM)]);
    assert!(accept_content(payload.as_slice()).is_ok());

    let module = loaded(&[Entry::Bytecode(parameter::VOTE_INTEREST, &RUNAWAY_PROGRAM)]);
    assert_eq!(
        module
            .active_configuration()
            .expect("handle")
            .vote_interest(),
        5
    );
}

#[test]
fn no_program_is_evaluated_at_acceptance() {
    // Neither form is run: an argument-taking program's result is unknowable
    // ahead of time, and an argument-less one is left to the same total runtime
    // mechanism rather than to a second, partial check.
    for id in [parameter::REGISTRATION_PRICE, parameter::VOTE_INTEREST] {
        let payload = frame(&[Entry::Bytecode(id, &UNDEFINED_OPCODE_PROGRAM)]);
        assert!(
            accept_content(payload.as_slice()).is_ok(),
            "identifier {id} should be accepted with an unevaluated program"
        );
    }
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
