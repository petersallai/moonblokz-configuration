/*! MoonBlokz chain-configuration module.

A MoonBlokz chain must run with parameters that are identical on every node: a
divergence in these values is a divergence in validation outcome. This crate
owns that agreement. It decodes the configuration content carried by chain-config
blocks (`payload_type = 3`), holds the FR8 tentative/durable commitment state,
resolves every parameter through a fixed registry of code-baked defaults, and
evaluates the small programs that compute the argument-dependent ones. The
blockchain consumes the result through per-parameter accessors and never
interprets a configuration key itself (FR56).

Authority: `moonblokz-info/moonblokz-configuration-specification.md`. Where this
crate's documentation is terser, the specification wins.

# Shape

- [`ChainConfiguration`] is the module: one retained content buffer, one
  commitment flag, and a change sink.
- [`ChainConfigTrait`] is the seam the blockchain is generic over.
- [`ActiveConfig`] is the accessor surface, reached only through
  [`ChainConfigTrait::active_configuration`]. It **borrows** the module, which is
  what makes FR56's no-caching rule structural rather than a documented request:
  the handle cannot outlive the invocation that acquired it, and it cannot be
  held across a mutation of the configuration state.
- [`accept_content`] is the acceptance pass: framing, registry conformance and
  the structural bounds, on the raw declared values, before anything is loaded.

# What is deliberately not here

No storage handle: the blockchain owns storage and performs every storage call,
passing content bytes in both directions (specification §8.2). No transport: the
firmware-side `Watch` that carries a radio snapshot implements
[`ConfigChangeSink`] on the node side, which is what keeps `embassy-sync` out of
this crate and preserves the dependency gate for `moonblokz-blockchain`. And no
signature verification: the FR7 content-signature check is an FR9 Tier-1 check
that runs in the blockchain, over the envelope
`moonblokz-chain-types` frames.
*/

#![no_std]

use core::num::NonZeroU16;

use moonblokz_chain_types::{
    ChainConfigBlockPayloadView, ConfigValueView, HEADER_SIZE, MAX_BLOCK_SIZE, MAX_PAYLOAD_SIZE,
};
use moonblokz_crypto::MAX_AGGREGATED_SIGNATURES;
use moonblokz_vm::{Fuel, HOST_RESOLVE_PARAMETER, Vm, VmHost, VmOutcome};

// ---------------------------------------------------------------------------
// Compile-time capacities
// ---------------------------------------------------------------------------

/// Per-block UTXO spent-bit width of the local build.
///
/// A chain declaring `max_block_utxo_output` above this cannot be represented by
/// the local node's cache, so the acceptance pass rejects it (FR8). The value is
/// pinned to the blockchain's real spent-bit width by a monomorphization-time
/// assertion **in the blockchain**, so the two cannot drift silently.
pub const UTXO_UNSPENT_BITS: u16 = 256;

/// Compile-time active-chain capacity of the local build.
///
/// The active-chain window length `W` is chain configuration — every node on a
/// chain must retain the same window or they do not agree on what has dropped
/// out of it — but a node cannot resize compile-time arrays from chain content.
/// The const generic is therefore a *capacity* and the chain-configured `W` must
/// fit inside it: a node whose capacity is below the chain's `W` cannot
/// participate and rejects the configuration, and a node whose capacity exceeds
/// it simply uses part of what it allocated. Pinned to the blockchain's own
/// bound by an assertion there, like [`UTXO_UNSPENT_BITS`].
pub const SNAKE_CHAIN_LENGTH_MAX: u16 = 500;

/// Length of the radio scoring matrix, the one array-typed parameter.
pub const SCORING_MATRIX_LEN: usize = 5;

/// Ceiling on the chain-declared `vm_fuel_limit`, **equal to the code-baked
/// default**.
///
/// The limit bounds how long one program evaluation may hold the core, and
/// acceptance pays that bound once per argument-less program — up to the 126
/// entries the key space allows — so an unbounded limit would let one content
/// hold the core for as long as it asked, against a watchdog.
///
/// Setting the ceiling *at* the default makes the budget a **downward-only** knob:
/// a chain may buy itself shorter evaluations, never longer ones. That is the only
/// direction that needs no new number — the default is the one value §12 grounds,
/// at roughly 9 ms on a static 55–70 cycles-per-instruction estimate — so raising
/// the ceiling above it would be inventing a bound no measurement supports. A
/// chain wanting more expensive computed parameters needs the default itself
/// re-based on hardware measurement, which is a firmware change and a
/// consensus-breaking one.
pub const VM_FUEL_LIMIT_MAX: u32 = 20_000;

// ---------------------------------------------------------------------------
// The machine
// ---------------------------------------------------------------------------

/// Operand-stack depth of the configuration VM (specification §12).
const VM_STACK_DEPTH: usize = 16;
/// Local-slot count of the configuration VM (specification §12).
const VM_LOCAL_SLOTS: usize = 8;
/// Maximum `GETPARAM` nesting depth (specification §12).
const VM_MAX_NESTING: usize = 3;

/// The machine every configuration program runs on. Its stack and slot array are
/// frame-resident, so the sizes above cost a stack frame rather than a static
/// footprint.
type ConfigVm = Vm<VM_STACK_DEPTH, VM_LOCAL_SLOTS, VM_MAX_NESTING>;

// ---------------------------------------------------------------------------
// The parameter registry
// ---------------------------------------------------------------------------

/// Wire identifiers of the parameter registry.
///
/// **This is permanent wire format.** Once a chain exists an identifier's
/// meaning cannot change: FR7 requires the content signature to be invariant for
/// the chain's lifetime and reproduced byte-identically in every FR49 replay
/// block. Identifiers are allocated densely from 1, are **never reused or
/// renumbered**, and a new parameter takes the next free one.
///
/// The key space is flat and shared by every consuming subsystem — blockchain,
/// radio and the VM alike — so that a single authority allocates identifiers and
/// two subsystems cannot pick the same one.
///
/// **Every duration is milliseconds in a `u32`.** That carries 49 days, against
/// defaults measured in seconds and minutes, so the width costs nothing and saves
/// four bytes on the wire per override. Callers that mix a duration into
/// timestamp arithmetic widen it at the use site, which is where the widening is
/// visible rather than assumed.
///
/// **The defaults are permanent too**, for a less obvious reason than the
/// identifiers: a chain that omits a parameter validates against this build's
/// default for it, so two firmware versions whose default tables differ by one
/// value validate the same chain differently — with no error on either side, which
/// is the same silent split the unknown-key rule exists to prevent. Changing a
/// value in the table below is a consensus-breaking change, not a tuning decision.
///
/// **Next free identifier: 30.**
pub mod parameter {
    /// FR45 (b) inter-block creation wait, milliseconds.
    pub const INTER_BLOCK_INTERVAL_MS: u8 = 1;
    /// FR47 grace-period window length, milliseconds.
    pub const GRACE_PERIOD_WINDOW_MS: u8 = 2;
    /// Block-size limit. Literal-only: its bound is what keeps the limit inside
    /// the compile-time block buffer, and only a declared value is checkable.
    pub const BLOCK_SIZE_LIMIT: u8 = 3;
    /// Maximum UTXO outputs per block, bounded by `UTXO_UNSPENT_BITS`.
    pub const MAX_BLOCK_UTXO_OUTPUT: u8 = 4;
    /// Maximum aggregated signatures per approval-evidence block (ADR-015).
    pub const MAX_AGGREGATED_SIGNATURES: u8 = 5;
    /// FR37 per-credit vote value; also the anti-capture interest denominator.
    pub const VOTE_SCALE: u8 = 6;
    /// FR37 anti-capture vote-interest rate.
    pub const VOTE_INTEREST: u8 = 7;
    /// FR19 / FR46 per-head parent-recovery retry window, milliseconds.
    pub const PARENT_RECOVERY_PER_HEAD_RETRY_INTERVAL_MS: u8 = 8;
    /// FR46 module-scope parent-recovery emit cooldown, milliseconds.
    pub const PARENT_RECOVERY_MIN_EMIT_INTERVAL_MS: u8 = 9;
    /// FR8 / ADR-015 required support count; `m = min(2·this − 1, |A|)`. May be
    /// computed: its floor is universal and its ceiling is the chain's own
    /// [`MAX_AGGREGATED_SIGNATURES`], applied as a clamp.
    pub const REQUIRED_SUPPORT: u8 = 10;

    /// Radio: minimum interval between echo requests, minutes.
    pub const ECHO_REQUEST_MINIMAL_INTERVAL: u8 = 11;
    /// Radio: target interval between echo messages, seconds.
    pub const ECHO_MESSAGES_TARGET_INTERVAL: u8 = 12;
    /// Radio: echo-gathering timeout, minutes.
    pub const ECHO_GATHERING_TIMEOUT: u8 = 13;
    /// Radio: delay between transmitted packets, milliseconds.
    pub const DELAY_BETWEEN_TX_PACKETS: u8 = 14;
    /// Radio: delay between transmitted messages, seconds.
    pub const DELAY_BETWEEN_TX_MESSAGES: u8 = 15;
    /// Radio: relay-position delay, seconds.
    pub const RELAY_POSITION_DELAY: u8 = 16;
    /// Radio: encoded connection-quality scoring matrix.
    pub const SCORING_MATRIX: u8 = 17;
    /// Radio: retry interval for missing packets, seconds.
    pub const RETRY_INTERVAL_FOR_MISSING_PACKETS: u8 = 18;
    /// Radio: maximum randomised transmit delay, milliseconds.
    pub const TX_MAXIMUM_RANDOM_DELAY: u8 = 19;

    /// FR45 (a) block fill threshold, percent.
    pub const BLOCK_FILL_THRESHOLD_PERCENT: u8 = 20;
    /// Active-chain window length `W`, bounded by `SNAKE_CHAIN_LENGTH_MAX`.
    pub const ACTIVE_CHAIN_LENGTH: u8 = 21;
    /// FR56 mempool replenishment interval, milliseconds.
    pub const MEMPOOL_REPLENISHMENT_INTERVAL_MS: u8 = 22;
    /// FR51 carry-forward custodian fee.
    pub const CUSTODIAN_FEE: u8 = 23;
    /// Registration price; takes the registered-node count as its argument.
    pub const REGISTRATION_PRICE: u8 = 24;
    /// FR56 minimum transaction fee per byte.
    pub const TX_FEE_PER_BYTE_MIN: u8 = 25;
    /// FR56 maximum transaction fee per byte.
    pub const TX_FEE_PER_BYTE_MAX: u8 = 26;
    /// FR29 deviation-replay insertion delay, milliseconds.
    pub const DEVIATION_REPLAY_INSERTION_DELAY_MS: u8 = 27;
    /// FR36 (c) replay-block reward.
    pub const REPLAY_BLOCK_REWARD: u8 = 28;

    /// Fuel budget of one program evaluation. Literal-only by rule.
    pub const VM_FUEL_LIMIT: u8 = 29;
}

/// What the registry records about one parameter.
///
/// Names are deliberately absent: they are a `config-encoder` convenience (a
/// program written for the encoder may reference a parameter as `@name`), and a
/// name table would be flash the firmware pays for a facility only the host tool
/// uses. The encoder holds the table and a test there pins it against this
/// registry, so the two cannot drift.
pub struct ParameterSpec {
    /// Wire identifier. Pinned to the table position by the density check below.
    pub id: u8,
    /// Exact literal width in bytes. A literal of any other length is malformed:
    /// no variable-length integer parsing, no ambiguity about zero-padding, and
    /// a width mismatch is a clean rejection rather than a reinterpretation.
    pub width: u8,
    /// Accessor arity — hence the argument count a `GETPARAM` naming this
    /// identifier must declare.
    pub args: u8,
    /// Whether a bytecode *override* is permitted.
    ///
    /// Literal-only parameters are those whose value must be knowable at
    /// acceptance time under every condition: the array-typed one (the VM has no
    /// array-valued result form), the execution-budget parameter itself
    /// (resolving it must not require running a program), and those carrying a
    /// bound that an argument-taking program could evade. A bound *alone* does
    /// not force literal-only — an argument-less program is evaluated once at
    /// acceptance and bound-checked exactly like a literal.
    pub bytecode_allowed: bool,
    /// Tier 2 — the code-baked default, itself either a literal or a program.
    pub default: DefaultValue,
    /// Tier 3 — the code-baked fallback literal, used when the tier above fails
    /// at evaluation time. For a literal default the two coincide, which is why
    /// the table's shorthand writes such a parameter's value once.
    pub fallback: u64,
}

/// What a parameter's code-baked default is.
///
/// A default may be a program with the same argument semantics as the accessor,
/// which is what makes tier 2 a real tier rather than a synonym for tier 3
/// (specification §5.1, PRD FR56). No parameter in the registry uses the program
/// form today; the representation exists so that adding one is a table edit
/// rather than a change to the resolution model.
pub enum DefaultValue {
    /// A plain constant.
    Literal(u64),
    /// A program, evaluated with its own fresh fuel budget.
    Program(&'static [u8]),
}

/// A parameter whose default is a literal: tiers 2 and 3 are that one value.
const fn spec_of(
    id: u8,
    width: u8,
    args: u8,
    bytecode_allowed: bool,
    default: u64,
) -> ParameterSpec {
    ParameterSpec {
        id,
        width,
        args,
        bytecode_allowed,
        default: DefaultValue::Literal(default),
        fallback: default,
    }
}

/// A parameter whose default is a program, with the fallback literal behind it.
///
/// Unused by the current table — see [`DefaultValue`].
#[allow(dead_code)]
const fn spec_of_program(
    id: u8,
    width: u8,
    args: u8,
    bytecode_allowed: bool,
    default: &'static [u8],
    fallback: u64,
) -> ParameterSpec {
    ParameterSpec {
        id,
        width,
        args,
        bytecode_allowed,
        default: DefaultValue::Program(default),
        fallback,
    }
}

/// The registry, in identifier order. See [`parameter`] for the identifiers and
/// the wire-format rules that govern them.
const REGISTRY: [ParameterSpec; 29] = [
    spec_of(parameter::INTER_BLOCK_INTERVAL_MS, 4, 0, true, 60_000),
    spec_of(parameter::GRACE_PERIOD_WINDOW_MS, 4, 0, true, 30_000),
    spec_of(parameter::BLOCK_SIZE_LIMIT, 2, 0, false, 2016),
    spec_of(parameter::MAX_BLOCK_UTXO_OUTPUT, 1, 0, false, 255),
    spec_of(parameter::MAX_AGGREGATED_SIGNATURES, 1, 0, false, 50),
    spec_of(parameter::VOTE_SCALE, 2, 0, true, 1000),
    spec_of(parameter::VOTE_INTEREST, 1, 0, true, 5),
    spec_of(
        parameter::PARENT_RECOVERY_PER_HEAD_RETRY_INTERVAL_MS,
        4,
        0,
        true,
        120_000,
    ),
    spec_of(
        parameter::PARENT_RECOVERY_MIN_EMIT_INTERVAL_MS,
        4,
        0,
        true,
        10_000,
    ),
    spec_of(parameter::REQUIRED_SUPPORT, 1, 0, true, 3),
    spec_of(parameter::ECHO_REQUEST_MINIMAL_INTERVAL, 2, 0, true, 1440),
    spec_of(parameter::ECHO_MESSAGES_TARGET_INTERVAL, 1, 0, true, 100),
    spec_of(parameter::ECHO_GATHERING_TIMEOUT, 1, 0, true, 10),
    spec_of(parameter::DELAY_BETWEEN_TX_PACKETS, 2, 0, true, 200),
    spec_of(parameter::DELAY_BETWEEN_TX_MESSAGES, 1, 0, true, 20),
    spec_of(parameter::RELAY_POSITION_DELAY, 1, 0, true, 10),
    spec_of(
        parameter::SCORING_MATRIX,
        SCORING_MATRIX_LEN as u8,
        0,
        false,
        // Array-typed values are carried verbatim; a value of at most eight
        // bytes round-trips through this crate's `u64` representation exactly,
        // so the default is the same little-endian byte sequence a literal
        // override would supply.
        u64::from_le_bytes([255, 243, 65, 82, 143, 0, 0, 0]),
    ),
    spec_of(
        parameter::RETRY_INTERVAL_FOR_MISSING_PACKETS,
        1,
        0,
        true,
        60,
    ),
    spec_of(parameter::TX_MAXIMUM_RANDOM_DELAY, 2, 0, true, 200),
    spec_of(parameter::BLOCK_FILL_THRESHOLD_PERCENT, 1, 0, true, 80),
    spec_of(parameter::ACTIVE_CHAIN_LENGTH, 2, 0, false, 500),
    spec_of(
        parameter::MEMPOOL_REPLENISHMENT_INTERVAL_MS,
        4,
        0,
        true,
        500_000,
    ),
    spec_of(parameter::CUSTODIAN_FEE, 8, 0, true, 1),
    spec_of(parameter::REGISTRATION_PRICE, 8, 1, true, 100),
    spec_of(parameter::TX_FEE_PER_BYTE_MIN, 8, 0, true, 0),
    spec_of(parameter::TX_FEE_PER_BYTE_MAX, 8, 0, true, 1000),
    spec_of(
        parameter::DEVIATION_REPLAY_INSERTION_DELAY_MS,
        4,
        0,
        true,
        300_000,
    ),
    spec_of(parameter::REPLAY_BLOCK_REWARD, 8, 0, true, 100),
    spec_of(parameter::VM_FUEL_LIMIT, 4, 0, false, 20_000),
];

// Identifiers are allocated densely from 1, so the record for an identifier sits
// at `id - 1` and the lookup needs no scan. Should a future allocation ever
// leave a gap, this fires and forces the lookup to be reconsidered
// deliberately rather than silently returning the wrong parameter's record.
const _: () = {
    let mut index = 0;
    while index < REGISTRY.len() {
        assert!(REGISTRY[index].id as usize == index + 1);
        // Every value is carried through a `u64`, which bounds the widths the
        // registry may declare.
        assert!(REGISTRY[index].width as usize <= 8);
        index += 1;
    }
};

/// Number of identifiers the registry allocates. The next free identifier is
/// `PARAMETER_COUNT + 1` while allocation stays dense.
pub const PARAMETER_COUNT: usize = REGISTRY.len();

/// The identifiers [`check_bound`] constrains.
///
/// Named as a table rather than left implicit in the `match`, so that the
/// registry invariant behind it can be asserted at compile time: a bound is only
/// enforceable on a value knowable at acceptance time, and an argument-taking
/// parameter's value is not, so a bounded parameter must have arity zero
/// (specification §6).
const BOUNDED_IDS: [u8; 10] = [
    parameter::BLOCK_SIZE_LIMIT,
    parameter::MAX_BLOCK_UTXO_OUTPUT,
    parameter::MAX_AGGREGATED_SIGNATURES,
    parameter::VOTE_SCALE,
    parameter::REQUIRED_SUPPORT,
    parameter::BLOCK_FILL_THRESHOLD_PERCENT,
    parameter::ACTIVE_CHAIN_LENGTH,
    parameter::TX_FEE_PER_BYTE_MIN,
    parameter::TX_FEE_PER_BYTE_MAX,
    parameter::VM_FUEL_LIMIT,
];

const _: () = {
    let mut index = 0;
    while index < BOUNDED_IDS.len() {
        assert!(REGISTRY[BOUNDED_IDS[index] as usize - 1].args == 0);
        index += 1;
    }
};

/// The identifiers whose bound is measured against a compile-time constant of the
/// **local build** rather than against a universal one.
///
/// These must stay literal-only, and the assertion below is what enforces it. The
/// reason is not taste: a bound like this is safe at acceptance, where a node that
/// cannot honour the declared value rejects the chain and stops participating — but
/// unsafe as a resolution-time fallback, which would keep the node participating
/// with a *different value* than a differently-built node resolves, with no error
/// on either side. Admitting a program here would put the bound on the resolution
/// path, so the form is the enforcement.
const PER_BUILD_LIMITED_IDS: [u8; 3] = [
    parameter::MAX_BLOCK_UTXO_OUTPUT,
    parameter::MAX_AGGREGATED_SIGNATURES,
    parameter::ACTIVE_CHAIN_LENGTH,
];

const _: () = {
    let mut index = 0;
    while index < PER_BUILD_LIMITED_IDS.len() {
        assert!(!REGISTRY[PER_BUILD_LIMITED_IDS[index] as usize - 1].bytecode_allowed);
        index += 1;
    }
};

// The ceiling equals the default, so the two cannot be edited apart: a default
// above its own ceiling would make the code-baked value itself unacceptable, and
// nothing else in the crate would notice. The match also pins §4.3's rule that the
// execution budget is a literal — resolving it must not require running a program.
const _: () = match &REGISTRY[parameter::VM_FUEL_LIMIT as usize - 1].default {
    DefaultValue::Literal(value) => assert!(*value <= VM_FUEL_LIMIT_MAX as u64),
    DefaultValue::Program(_) => panic!("the execution budget must be a literal"),
};

// The retained payload's length fields are `u16`. Truncating them would leave the
// retained slices short — a signature over the wrong bytes, and an FR8 comparison
// against the wrong bytes, with no panic to notice.
const _: () = assert!(MAX_PAYLOAD_SIZE <= u16::MAX as usize);

/// Whether the registry allocates `id`. An unallocated identifier is **rejected,
/// never skipped**: a node substituting its own default for a parameter it does
/// not know would validate against different values than the rest of the
/// network — a consensus split that produces no error anywhere.
fn is_allocated(id: u8) -> bool {
    id >= 1 && id as usize <= REGISTRY.len()
}

/// The registry record of an allocated identifier.
fn spec(id: u8) -> &'static ParameterSpec {
    &REGISTRY[id as usize - 1]
}

/// The registry record for `id`, or `None` if the registry does not allocate it.
///
/// The host-side `config-encoder` reads the registry through this: it needs the
/// literal width to encode a value, the arity to check a `GETPARAM`, and the
/// permitted value form to refuse a program where one is not allowed. Runtime
/// paths use the infallible lookup above.
pub fn parameter_spec(id: u8) -> Option<&'static ParameterSpec> {
    if is_allocated(id) {
        Some(spec(id))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why configuration content was refused, or a state operation declined.
///
/// Every content variant is exact evidence of invalidity per FR16 and leaves no
/// configuration loaded. Derives are omitted outside tests — every trait impl
/// costs binary size on embedded targets.
#[cfg_attr(test, derive(Debug))]
pub enum ChainConfigError {
    /// The envelope framing is malformed: too short, a `value_length` past the
    /// end, a content end that does not account for the whole payload, a
    /// duplicate identifier, or a key byte outside the usable range.
    MalformedContent,
    /// The content names an identifier this firmware does not allocate,
    /// carrying the offending key byte.
    ///
    /// This is the operator-facing case: the content of a chain's configuration
    /// defines the minimum firmware capability required to participate, so a
    /// node older than a key the chain uses will never converge. Logged
    /// distinguishably (`chain-config-unknown-key`) so the diagnosis reads *the
    /// node is out of date* rather than *a bad block arrived*.
    UnknownParameter(u8),
    /// A literal's `value_length` does not equal the parameter's declared width.
    ValueWidthMismatch(u8),
    /// A bytecode value appears under a literal-only parameter.
    BytecodeNotPermitted(u8),
    /// A declared value violates one of the structural bounds.
    BoundViolation(u8),
    /// A load or promotion was attempted while the configuration is durably
    /// locked. The durable configuration is set-once for the lifetime of the
    /// chain.
    DurableLocked,
    /// Promotion was attempted with no configuration loaded.
    NotLoaded,
}

// ---------------------------------------------------------------------------
// Commitment state and change notification
// ---------------------------------------------------------------------------

/// Which FR8 commitment the loaded content carries.
///
/// It lives on the handle so that a value and the commitment state that produced
/// it cannot be read from two different points in time.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Commitment {
    /// Loaded during collecting state, not yet committed (FR8).
    Tentative,
    /// Committed once and locked for the lifetime of the chain (FR8, FR54).
    Durable,
}

/// Notified on every configuration state transition, at the moment it happens.
///
/// The module drives notification itself rather than exposing a counter for a
/// runtime to poll, and rather than routing it through the blockchain's
/// single-outcome channel — which would consume an emission slot, need a
/// scheduler priority rule, and force the module to remember whether the
/// notification had been delivered.
///
/// The sink is a **mandatory generic parameter** of [`ChainConfiguration`], so
/// [`NoopConfigChangeSink`] — used by tests and by any consumer that does not
/// care — optimises away entirely and no runtime branch is paid per change.
pub trait ConfigChangeSink {
    /// Called after the transition, with a handle over the now-current content.
    fn on_configuration_changed(&self, config: &ActiveConfig<'_>);
}

/// The zero-sized sink for consumers that do not observe configuration changes.
pub struct NoopConfigChangeSink;

impl ConfigChangeSink for NoopConfigChangeSink {
    fn on_configuration_changed(&self, _config: &ActiveConfig<'_>) {}
}

// The no-op sink optimising away is a property consumers are promised, not an
// accident of today's definition: a field added here would silently cost every
// blockchain-only configuration a byte and a branch.
const _: () = assert!(core::mem::size_of::<NoopConfigChangeSink>() == 0);

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

/// The configuration seam the blockchain is generic over.
///
/// Availability is decided once, at handle acquisition, rather than per
/// accessor: a caller that gets `None` from
/// [`active_configuration`](Self::active_configuration) cannot proceed with any
/// configuration-derived work, and the blockchain treats that as the signal that
/// the corresponding FR9 staged-validation step cannot yet be performed.
///
/// The FR8 state operations are here, and the lifecycle that decides *when* to
/// call them stays with the blockchain (architecture §11). Content bytes are the
/// whole chain-config block payload — the content region plus its FR7 content
/// signature — exactly as `BlockView::payload()` returns it.
pub trait ChainConfigTrait {
    /// The accessor surface over the loaded content, or `None` while none is
    /// loaded.
    fn active_configuration(&self) -> Option<ActiveConfig<'_>>;

    /// Accepts `payload` and loads it tentatively (FR8), replacing any content
    /// already held tentatively. Refused once the configuration is durably
    /// locked.
    fn load_tentative(&mut self, payload: &[u8]) -> Result<(), ChainConfigError>;

    /// Accepts `payload` and loads it durably — the FR54 genesis lock and the
    /// startup path that finds a durable configuration in the control plane.
    fn load_durable(&mut self, payload: &[u8]) -> Result<(), ChainConfigError>;

    /// Commits the tentative content and locks it for the lifetime of the chain
    /// (FR8). A second promotion is **refused**, not silently re-applied.
    fn promote_durable(&mut self) -> Result<(), ChainConfigError>;

    /// Drops the tentative content — the FR8 mismatch path — returning the
    /// module to absent before it adopts a new tentative. A durable
    /// configuration is never destroyed.
    fn discard_tentative(&mut self);

    /// The tentative content region, or `None` unless content is held
    /// tentatively. This is what the FR8 ready transition compares
    /// byte-identically against the candidate segment's chain-config content.
    fn tentative_content(&self) -> Option<&[u8]>;

    /// The durable content region, or `None` until the configuration is locked.
    fn durable_content(&self) -> Option<&[u8]>;

    /// FR8 durable-lock status.
    fn is_durable_locked(&self) -> bool;
}

// ---------------------------------------------------------------------------
// The module
// ---------------------------------------------------------------------------

/// The chain-configuration module: one retained payload, one commitment flag.
///
/// **Single buffer (NFR1).** Tentative and durable content are never two
/// different values at once — promotion flips the flag over the same retained
/// bytes. The footprint is one [`MAX_PAYLOAD_SIZE`] buffer plus the flag, equal
/// to the retention the blockchain performed before this module existed.
pub struct ChainConfiguration<Sink: ConfigChangeSink> {
    payload: [u8; MAX_PAYLOAD_SIZE],
    payload_len: u16,
    /// Derived by the acceptance walk at load time, so the content region is not
    /// re-derived on every read.
    content_len: u16,
    /// `None` is the absent state; the buffer above is then simply unread.
    commitment: Option<Commitment>,
    sink: Sink,
}

impl<Sink: ConfigChangeSink> ChainConfiguration<Sink> {
    /// A module holding no configuration.
    pub const fn new(sink: Sink) -> Self {
        Self {
            payload: [0u8; MAX_PAYLOAD_SIZE],
            payload_len: 0,
            content_len: 0,
            commitment: None,
            sink,
        }
    }

    /// Accepts and retains `payload`, then notifies the sink.
    fn load(&mut self, payload: &[u8], commitment: Commitment) -> Result<(), ChainConfigError> {
        if self.is_durable_locked() {
            return Err(ChainConfigError::DurableLocked);
        }
        // Acceptance runs before anything is retained, so a refusal leaves the
        // previous state exactly as it was. The retention bound is part of that
        // pass, not a separate check here, so `config-encoder`'s guarantee — what
        // the tool accepts, the network accepts — covers it too.
        let content_len = accept_content(payload)?;

        self.payload[..payload.len()].copy_from_slice(payload);
        self.payload_len = payload.len() as u16;
        self.content_len = content_len as u16;
        self.commitment = Some(commitment);
        self.notify();
        Ok(())
    }

    fn notify(&self) {
        if let Some(config) = self.active_configuration() {
            self.sink.on_configuration_changed(&config);
        }
    }

    /// The retained payload — content region plus content signature.
    fn retained_payload(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }

    /// The retained content region: the canonical bytes node #0 signed.
    fn retained_content(&self) -> &[u8] {
        &self.payload[..self.content_len as usize]
    }
}

impl<Sink: ConfigChangeSink> ChainConfigTrait for ChainConfiguration<Sink> {
    fn active_configuration(&self) -> Option<ActiveConfig<'_>> {
        Some(ActiveConfig {
            // The payload was accepted before it was retained, so the walk
            // succeeds; answering `None` if it ever did not is the safe total
            // behaviour — a handle over content this build cannot read would be
            // worse than no handle.
            view: ChainConfigBlockPayloadView::from_payload(self.retained_payload())?,
            commitment: self.commitment?,
        })
    }

    fn load_tentative(&mut self, payload: &[u8]) -> Result<(), ChainConfigError> {
        self.load(payload, Commitment::Tentative)
    }

    fn load_durable(&mut self, payload: &[u8]) -> Result<(), ChainConfigError> {
        self.load(payload, Commitment::Durable)
    }

    fn promote_durable(&mut self) -> Result<(), ChainConfigError> {
        match self.commitment {
            None => Err(ChainConfigError::NotLoaded),
            Some(Commitment::Durable) => Err(ChainConfigError::DurableLocked),
            Some(Commitment::Tentative) => {
                self.commitment = Some(Commitment::Durable);
                self.notify();
                Ok(())
            }
        }
    }

    fn discard_tentative(&mut self) {
        if self.commitment == Some(Commitment::Tentative) {
            self.commitment = None;
            self.payload_len = 0;
            self.content_len = 0;
        }
    }

    fn tentative_content(&self) -> Option<&[u8]> {
        match self.commitment {
            Some(Commitment::Tentative) => Some(self.retained_content()),
            _ => None,
        }
    }

    fn durable_content(&self) -> Option<&[u8]> {
        match self.commitment {
            Some(Commitment::Durable) => Some(self.retained_content()),
            _ => None,
        }
    }

    fn is_durable_locked(&self) -> bool {
        self.commitment == Some(Commitment::Durable)
    }
}

// ---------------------------------------------------------------------------
// The accessor surface
// ---------------------------------------------------------------------------

/// Borrowed accessor surface over the loaded configuration.
///
/// Every accessor re-resolves: the value is read at the moment it is needed and
/// is not retained (FR56). Because the last resolution tier is a constant,
/// **every accessor on an obtained handle returns a value** — there is no
/// not-available case to handle per parameter.
pub struct ActiveConfig<'a> {
    /// The envelope, walked and validated **once** when the handle was acquired.
    /// Every accessor re-resolves against it, but none re-validates the framing:
    /// re-deriving the content boundary per accessor — twice per accessor, in
    /// fact, and again per nested `GETPARAM` — was measurable work for no
    /// information.
    view: ChainConfigBlockPayloadView<'a>,
    commitment: Commitment,
}

impl<'a> ActiveConfig<'a> {
    /// Which FR8 commitment produced these values.
    pub fn commitment(&self) -> Commitment {
        self.commitment
    }

    // -- Blockchain parameters --

    /// FR45 (b) inter-block creation wait, milliseconds.
    pub fn inter_block_interval_ms(&self) -> u32 {
        narrow_u32(self.resolve(parameter::INTER_BLOCK_INTERVAL_MS, &[]))
    }

    /// FR47 grace-period window length, milliseconds.
    pub fn grace_period_window_ms(&self) -> u32 {
        narrow_u32(self.resolve(parameter::GRACE_PERIOD_WINDOW_MS, &[]))
    }

    /// Chain-config block-size limit, at most `MAX_BLOCK_SIZE`.
    pub fn block_size_limit(&self) -> u16 {
        narrow_u16(self.resolve(parameter::BLOCK_SIZE_LIMIT, &[]))
    }

    /// Maximum UTXO outputs per block.
    ///
    /// `u8` is correct *because* the FR8 bound moved upstream: acceptance sees
    /// the raw declared value, where an out-of-range number is representable and
    /// is rejected, so only legal values reach this accessor.
    pub fn max_utxo_outputs(&self) -> u8 {
        narrow_u8(self.resolve(parameter::MAX_BLOCK_UTXO_OUTPUT, &[]))
    }

    /// Maximum aggregated signatures per approval-evidence block (ADR-015).
    pub fn max_aggregated_signatures(&self) -> u8 {
        narrow_u8(self.resolve(parameter::MAX_AGGREGATED_SIGNATURES, &[]))
    }

    /// FR37 `vote_scale` — the per-credit vote value, and the anti-capture
    /// interest denominator, which is why zero is refused at acceptance.
    pub fn vote_scale(&self) -> NonZeroU16 {
        // Acceptance refuses a declared zero and the parameter is literal-only,
        // so accepted content cannot reach the `unwrap_or`: it is tier 3, the
        // code-baked fallback literal, and this is the one accessor whose return
        // type makes that tier visible in the signature.
        NonZeroU16::new(narrow_u16(self.resolve(parameter::VOTE_SCALE, &[])))
            .unwrap_or(FALLBACK_VOTE_SCALE)
    }

    /// FR37 anti-capture vote-interest rate.
    pub fn vote_interest(&self) -> u8 {
        narrow_u8(self.resolve(parameter::VOTE_INTEREST, &[]))
    }

    /// FR19 / FR46 per-head parent-recovery retry window, milliseconds.
    pub fn parent_recovery_per_head_retry_interval_ms(&self) -> u32 {
        narrow_u32(self.resolve(parameter::PARENT_RECOVERY_PER_HEAD_RETRY_INTERVAL_MS, &[]))
    }

    /// FR46 module-scope parent-recovery emit cooldown, milliseconds.
    pub fn parent_recovery_min_emit_interval_ms(&self) -> u32 {
        narrow_u32(self.resolve(parameter::PARENT_RECOVERY_MIN_EMIT_INTERVAL_MS, &[]))
    }

    /// ADR-015 required support count, **clamped to the chain's own
    /// `max_aggregated_signatures`**.
    ///
    /// The clamp is what lets this parameter be computed. Its floor (`>= 1`) is
    /// universal, so the resolution guard can enforce it on a computed value; its
    /// ceiling is not — only the *chain* may state it, because a ceiling taken from
    /// a build constant would make the clamp decision differ between builds. So the
    /// chain declares the ceiling as a literal (identifier 5, bound-checked against
    /// the backend at acceptance, where the answer to a value this build cannot
    /// honour is rejection rather than substitution), and the clamp reads it back
    /// from the same content every node holds.
    ///
    /// Clamping rather than falling back is deliberate, and matches ADR-015's own
    /// `m = min(2·required_support − 1, |A|)`: it keeps a computed value's intent —
    /// grow with the network, never exceed what the evidence can carry — where a
    /// fallback would discard the computation for the code-baked default.
    pub fn required_support(&self) -> u8 {
        narrow_u8(self.resolve(parameter::REQUIRED_SUPPORT, &[]))
            .min(self.max_aggregated_signatures())
    }

    /// FR45 (a) block fill threshold, percent.
    pub fn block_fill_threshold_percent(&self) -> u8 {
        narrow_u8(self.resolve(parameter::BLOCK_FILL_THRESHOLD_PERCENT, &[]))
    }

    /// Active-chain window length `W`, at most [`SNAKE_CHAIN_LENGTH_MAX`].
    pub fn active_chain_length(&self) -> u16 {
        narrow_u16(self.resolve(parameter::ACTIVE_CHAIN_LENGTH, &[]))
    }

    /// FR56 mempool replenishment interval, milliseconds.
    ///
    /// `u32` is ample: it carries 49 days of milliseconds against a default of
    /// eight and a half minutes.
    pub fn mempool_replenishment_interval_ms(&self) -> u32 {
        narrow_u32(self.resolve(parameter::MEMPOOL_REPLENISHMENT_INTERVAL_MS, &[]))
    }

    /// FR51 carry-forward custodian fee.
    pub fn custodian_fee(&self) -> u64 {
        self.resolve(parameter::CUSTODIAN_FEE, &[])
    }

    /// Registration price at a given registered-node count.
    ///
    /// The arity is part of the registry, so it holds even while the default is
    /// a plain literal that does not vary with the argument: a chain wanting a
    /// size-dependent price overrides the key with a program of the same arity.
    pub fn registration_price(&self, registered_nodes: u32) -> u64 {
        self.resolve(parameter::REGISTRATION_PRICE, &[registered_nodes as u64])
    }

    /// FR56 minimum transaction fee per byte.
    pub fn tx_fee_per_byte_min(&self) -> u64 {
        self.resolve(parameter::TX_FEE_PER_BYTE_MIN, &[])
    }

    /// FR56 maximum transaction fee per byte.
    pub fn tx_fee_per_byte_max(&self) -> u64 {
        self.resolve(parameter::TX_FEE_PER_BYTE_MAX, &[])
    }

    /// FR29 deviation-replay insertion delay, milliseconds.
    pub fn deviation_replay_insertion_delay_ms(&self) -> u32 {
        narrow_u32(self.resolve(parameter::DEVIATION_REPLAY_INSERTION_DELAY_MS, &[]))
    }

    /// FR36 (c) replay-block reward.
    pub fn replay_block_reward(&self) -> u64 {
        self.resolve(parameter::REPLAY_BLOCK_REWARD, &[])
    }

    // -- Radio parameters (argument-less by rule) --

    /// Minimum interval between echo requests, minutes.
    pub fn echo_request_minimal_interval(&self) -> u16 {
        narrow_u16(self.resolve(parameter::ECHO_REQUEST_MINIMAL_INTERVAL, &[]))
    }

    /// Target interval between echo messages, seconds.
    pub fn echo_messages_target_interval(&self) -> u8 {
        narrow_u8(self.resolve(parameter::ECHO_MESSAGES_TARGET_INTERVAL, &[]))
    }

    /// Echo-gathering timeout, minutes.
    pub fn echo_gathering_timeout(&self) -> u8 {
        narrow_u8(self.resolve(parameter::ECHO_GATHERING_TIMEOUT, &[]))
    }

    /// Delay between transmitted packets, milliseconds.
    pub fn delay_between_tx_packets(&self) -> u16 {
        narrow_u16(self.resolve(parameter::DELAY_BETWEEN_TX_PACKETS, &[]))
    }

    /// Delay between transmitted messages, seconds.
    pub fn delay_between_tx_messages(&self) -> u8 {
        narrow_u8(self.resolve(parameter::DELAY_BETWEEN_TX_MESSAGES, &[]))
    }

    /// Relay-position delay, seconds.
    pub fn relay_position_delay(&self) -> u8 {
        narrow_u8(self.resolve(parameter::RELAY_POSITION_DELAY, &[]))
    }

    /// Encoded connection-quality scoring matrix.
    ///
    /// Literal-only because it is not a scalar: the VM returns a `u64` and has
    /// no array-valued result form. The bytes are carried verbatim, and a value
    /// of at most eight bytes round-trips through the `u64` resolution path
    /// unchanged.
    pub fn scoring_matrix(&self) -> [u8; SCORING_MATRIX_LEN] {
        let value = self.resolve(parameter::SCORING_MATRIX, &[]).to_le_bytes();
        let mut matrix = [0u8; SCORING_MATRIX_LEN];
        matrix.copy_from_slice(&value[..SCORING_MATRIX_LEN]);
        matrix
    }

    /// Retry interval for missing packets, seconds.
    pub fn retry_interval_for_missing_packets(&self) -> u8 {
        narrow_u8(self.resolve(parameter::RETRY_INTERVAL_FOR_MISSING_PACKETS, &[]))
    }

    /// Maximum randomised transmit delay, milliseconds.
    pub fn tx_maximum_random_delay(&self) -> u16 {
        narrow_u16(self.resolve(parameter::TX_MAXIMUM_RANDOM_DELAY, &[]))
    }

    // -- VM parameters --

    /// Fuel budget of one program evaluation.
    pub fn vm_fuel_limit(&self) -> u32 {
        narrow_u32(self.resolve(parameter::VM_FUEL_LIMIT, &[]))
    }

    // -- Resolution --

    /// Resolves `id` over `args` through the three tiers.
    ///
    /// Tier 1 is the chain-config override, tier 2 the code-baked default, tier 3
    /// the code-baked fallback literal. A tier fails — and resolution moves to the
    /// next — when its program traps, exhausts its budget, or **returns a value
    /// outside the parameter's bound**; the last of those is what lets a bounded
    /// parameter admit a program, since acceptance cannot check a computed value.
    /// **Each tier that needs a budget starts a fresh one**: if a lower tier inherited an exhausted budget, then whenever
    /// exhaustion was the failure cause the tier below could never run, and it
    /// would be dead code. Sharing happens along the other axis — a nested
    /// `GETPARAM` draws from the budget of the invocation that started it, so a
    /// program cannot evade the bound by composing sub-evaluations.
    fn resolve(&self, id: u8, args: &[u64]) -> u64 {
        let mut fuel = Fuel::new(self.fuel_limit());
        self.resolve_with(spec(id), args, &mut fuel)
    }

    /// Resolution against a caller-supplied budget — the nesting path.
    fn resolve_with(&self, spec: &ParameterSpec, args: &[u64], fuel: &mut Fuel) -> u64 {
        // Tier 1 — the chain-config override, on the caller's budget.
        if let Some(entry) = self.entry(spec.id)
            && let Some(value) = self.evaluate(&entry, spec, args, fuel)
        {
            return value;
        }
        // Tier 2 — the code-baked default. A program default gets its own fresh
        // budget, which is the whole reason the tiers are separate.
        match spec.default {
            DefaultValue::Literal(value) => return value,
            DefaultValue::Program(program) => {
                let mut tier_fuel = Fuel::new(self.fuel_limit());
                if let VmOutcome::Completed(value) =
                    ConfigVm::execute(program, args, &mut tier_fuel, self)
                    && let Some(value) = bounded(spec.id, value)
                {
                    return value;
                }
            }
        }
        // Tier 3 — the code-baked fallback literal. A constant, which is what
        // makes the accessor surface total.
        spec.fallback
    }

    /// The entry for `id` in the loaded content, if the content overrides it.
    fn entry(&self, id: u8) -> Option<ConfigValueView<'a>> {
        self.view.iter().find(|entry| entry.parameter_id() == id)
    }

    /// Evaluates one override entry, or `None` when the tier fails.
    fn evaluate(
        &self,
        entry: &ConfigValueView<'_>,
        spec: &ParameterSpec,
        args: &[u64],
        fuel: &mut Fuel,
    ) -> Option<u64> {
        if entry.is_bytecode() {
            if !spec.bytecode_allowed {
                return None;
            }
            match ConfigVm::execute(entry.value(), args, fuel, self) {
                // A computed value has to clear the same bound a declared literal
                // does. Acceptance cannot check it — it evaluates nothing — so the
                // check happens here, and a violation is treated exactly like a
                // trap: this tier failed, resolution moves on. That is what lets a
                // bounded parameter admit a program at all.
                VmOutcome::Completed(value) => bounded(spec.id, value),
                // Both non-`Completed` outcomes map onto the next tier: nothing
                // is observable to the accessor's caller, whose surface stays
                // total.
                VmOutcome::Trapped(_) | VmOutcome::OutOfFuel => None,
            }
        } else if entry.value().len() == spec.width as usize {
            Some(read_le(entry.value()))
        } else {
            None
        }
    }

    /// The budget one program evaluation may spend.
    ///
    /// `vm_fuel_limit` is literal-only precisely so that this cannot recurse:
    /// bounding every evaluation must not itself require running a program.
    fn fuel_limit(&self) -> u32 {
        narrow_u32(declared_fuel_limit(&self.view))
    }
}

impl VmHost for ActiveConfig<'_> {
    fn call(&self, func_id: u16, selector: u8, args: &[u64], fuel: &mut Fuel) -> Option<u64> {
        if func_id != HOST_RESOLVE_PARAMETER || !is_allocated(selector) {
            return None;
        }
        let spec = spec(selector);
        // `args.len()` is the count the *program* declared. The registry holds
        // the arity, and the VM deliberately does not, so validating that the
        // two agree is this seam's responsibility and no one else's.
        if args.len() != spec.args as usize {
            return None;
        }
        // The nested evaluation draws from the caller's budget, so exhaustion
        // aborts the whole invocation rather than just this sub-evaluation.
        Some(self.resolve_with(spec, args, fuel))
    }
}

/// The declared `vm_fuel_limit` of a content region, or its code-baked default.
///
/// One reader for a consensus-visible number that both resolution and acceptance
/// need: two paths to it would be one edit away from disagreeing. The parameter is
/// literal-only precisely so that reading it cannot recurse — bounding every
/// evaluation must not itself require running a program (specification §4.3).
fn declared_fuel_limit(view: &ChainConfigBlockPayloadView<'_>) -> u64 {
    let spec = spec(parameter::VM_FUEL_LIMIT);
    let declared = view
        .iter()
        .find(|entry| entry.parameter_id() == spec.id)
        .filter(|entry| !entry.is_bytecode() && entry.value().len() == spec.width as usize)
        .map(|entry| read_le(entry.value()));
    match declared {
        Some(value) => value,
        None => spec.fallback,
    }
}

/// The fallback literal behind [`ActiveConfig::vote_scale`].
const FALLBACK_VOTE_SCALE: NonZeroU16 = match NonZeroU16::new(1000) {
    Some(value) => value,
    None => panic!("the vote-scale fallback literal is non-zero"),
};

/// Reads a little-endian value of up to eight bytes.
fn read_le(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    let mut index = 0;
    while index < bytes.len() && index < 8 {
        value |= (bytes[index] as u64) << (8 * index);
        index += 1;
    }
    value
}

// Narrowing is by **saturation**, consistent with the saturating arithmetic of
// the VM itself. Parameters carrying a structural invariant are not left to
// saturation — they are constrained at acceptance instead.
fn narrow_u8(value: u64) -> u8 {
    if value > u8::MAX as u64 {
        u8::MAX
    } else {
        value as u8
    }
}

fn narrow_u16(value: u64) -> u16 {
    if value > u16::MAX as u64 {
        u16::MAX
    } else {
        value as u16
    }
}

fn narrow_u32(value: u64) -> u32 {
    if value > u32::MAX as u64 {
        u32::MAX
    } else {
        value as u32
    }
}

// ---------------------------------------------------------------------------
// Acceptance
// ---------------------------------------------------------------------------

/// Accepts chain-config content, returning the length of its content region.
///
/// Runs on the **raw declared values**, before anything is loaded: this is the
/// only place where an out-of-range declared value is still visible, since once
/// a value has passed through a narrowing accessor it can no longer be
/// distinguished from a legal one. Rejection is exact evidence of invalidity per
/// FR16.
///
/// `payload` is the whole chain-config block payload — the content region plus
/// its FR7 content signature. Verifying that signature is the blockchain's FR9
/// Tier-1 responsibility and is deliberately not repeated here.
///
/// Three passes, in order:
///
/// 1. **Framing**, by `moonblokz-chain-types`: length, entry walk, derived
///    content end, duplicate identifiers, key-byte range.
/// 2. **Registry conformance**: identifier allocated, literal width exact,
///    bytecode only where the registry permits it.
/// 3. **Declared literals**: the structural bounds, on the values the content
///    states outright, plus the one invariant that spans two parameters.
///
/// **No program is run here.** Checking a program's result ahead of time is only
/// possible when it takes no arguments, so such a pass is partial by construction
/// and grows more partial with every argument-taking parameter the registry gains.
/// A misbehaving program is already covered completely by the resolution model: a
/// trap or an exhausted budget fails that tier and the value falls through to the
/// code-baked default and then to the fallback literal, identically on every node
/// (§7.3). The bounds that must hold for a node to *represent* the chain all sit on
/// literal-only parameters and are therefore still checked below.
pub fn accept_content(payload: &[u8]) -> Result<usize, ChainConfigError> {
    // The retention buffer is fixed, so content this node could not hold is not
    // content it can accept. Checked here rather than at the load site so that the
    // public pass is the whole acceptance rule.
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(ChainConfigError::MalformedContent);
    }

    let view = ChainConfigBlockPayloadView::from_payload(payload)
        .ok_or(ChainConfigError::MalformedContent)?;

    // Pass 1 — registry conformance, every entry.
    for entry in view.iter() {
        let id = entry.parameter_id();
        let Some(spec) = parameter_spec(id) else {
            // `chain-config-unknown-key`: the key byte travels with the error so
            // the log record can name it (FR64 wires the emission).
            return Err(ChainConfigError::UnknownParameter(entry.key_byte()));
        };
        if entry.is_bytecode() {
            if !spec.bytecode_allowed {
                return Err(ChainConfigError::BytecodeNotPermitted(id));
            }
        } else if entry.value().len() != spec.width as usize {
            return Err(ChainConfigError::ValueWidthMismatch(id));
        }
    }

    // Pass 2 — the structural bounds, on the declared literals.
    //
    // **Bytecode overrides are not evaluated here.** A program's result can only
    // be checked ahead of time when it takes no arguments, so any such pass is
    // partial by construction — and it becomes more partial with every
    // argument-taking parameter the registry gains. The runtime already has the
    // complete mechanism for a program that misbehaves: a trap or an exhausted
    // budget fails that tier and resolution falls through to the code-baked
    // default and then to the fallback literal, deterministically and identically
    // on every node (§7.3). Trusting one total mechanism is worth more than
    // adding a second, incomplete one in front of it.
    //
    // What that leaves uncovered is bounded by the registry's own value forms.
    // Every parameter whose bound must hold for the local node to *represent* the
    // chain at all — the spent-bit width, the active-chain capacity, the
    // aggregation ceiling, the vote denominator, the execution budget — is
    // literal-only, so its declared value is checked below. The two bounded
    // parameters that do admit a program (`block_size_limit`,
    // `block_fill_threshold_percent`) can only be driven out of range into a
    // *weaker rule* the whole chain applies alike — a limit that never binds, a
    // fill threshold that never triggers — never into a value this node cannot
    // hold. That is founder self-harm on a node-#0-signed content, not a
    // consensus split and not a representation failure.
    let mut tx_fee_min = None;
    let mut tx_fee_max = None;

    for entry in view.iter() {
        if entry.is_bytecode() {
            continue;
        }
        let spec = spec(entry.parameter_id());
        let declared = read_le(entry.value());

        check_bound(spec.id, declared)?;

        match spec.id {
            parameter::TX_FEE_PER_BYTE_MIN => tx_fee_min = Some(declared),
            parameter::TX_FEE_PER_BYTE_MAX => tx_fee_max = Some(declared),
            _ => {}
        }
    }

    // Pass 3 — the one invariant that spans two parameters, and therefore cannot
    // live in a per-parameter check. A parameter absent from the content — or
    // overridden by a program, whose result is not knowable here — contributes its
    // code-baked default, which is the value resolution falls back to.
    let declared_or_default = |declared: Option<u64>, id: u8| match declared {
        Some(value) => value,
        None => spec(id).fallback,
    };
    if declared_or_default(tx_fee_min, parameter::TX_FEE_PER_BYTE_MIN)
        > declared_or_default(tx_fee_max, parameter::TX_FEE_PER_BYTE_MAX)
    {
        return Err(ChainConfigError::BoundViolation(
            parameter::TX_FEE_PER_BYTE_MIN,
        ));
    }

    Ok(view.content().len())
}

/// A computed value, if it clears its parameter's bound.
///
/// The resolution counterpart of [`check_bound`], and deliberately the same
/// predicate: "valid" is defined once, and a program is held to exactly the
/// standard a declared literal is. Returning `None` makes an out-of-range result
/// a *tier failure* rather than a value, so resolution falls through to the
/// code-baked default and then to the fallback literal — which is what allows a
/// parameter to carry a bound and still admit a program.
///
/// # A bound that is not universal must not reach this
///
/// At acceptance, a bound measured against a compile-time constant of *this build*
/// is safe: a node that cannot honour the value rejects the chain and stops
/// participating, so there is no divergence. Here it is different — a fallback
/// keeps the node participating with a *different value*, so if two builds
/// disagreed about the bound they would disagree about the value, with no error on
/// either side. Every bound reachable from here must therefore hold identically on
/// every build. That is why `UTXO_UNSPENT_BITS` (ID 4) and `SNAKE_CHAIN_LENGTH_MAX`
/// (ID 21) belong to literal-only parameters: their limits are per-build, so the
/// decision has to stay at acceptance, where the answer is rejection rather than
/// substitution. Every bound this function can reach is universal — 0, 1, 100, and
/// the block format's own `HEADER_SIZE` and `MAX_BLOCK_SIZE`. ID 10's ceiling was
/// the one exception and is no longer here: it became a clamp against the chain's
/// own declared value instead (see [`ActiveConfig::required_support`]).
fn bounded(id: u8, value: u64) -> Option<u64> {
    match check_bound(id, value) {
        Ok(()) => Some(value),
        Err(_) => None,
    }
}

/// The structural bounds, applied to a declared value.
///
/// Each is a place where the chain states a requirement and a compile-time
/// constant states what this build can honour. A parameter with no bound passes.
fn check_bound(id: u8, declared: u64) -> Result<(), ChainConfigError> {
    let within = match id {
        // FR8: above the local per-block spent-bit width the cache cannot
        // represent the outputs; at zero no transaction output could ever be
        // included. The upper end is unreachable through a legal literal while the
        // width is one byte — a wider value fails the exact-width rule first — but
        // it is the pin that catches a build with a narrower cache.
        parameter::MAX_BLOCK_UTXO_OUTPUT => declared >= 1 && declared <= UTXO_UNSPENT_BITS as u64,
        // FR8 / ADR-015: below 1, `m = min(2·required_support − 1, |A|)` yields
        // `m = -1`. Only the floor lives here, and deliberately so: it is universal,
        // so the resolution guard may enforce it on a computed value. The ceiling is
        // the chain's own `max_aggregated_signatures`, applied as a clamp by the
        // accessor — see [`ActiveConfig::required_support`].
        parameter::REQUIRED_SUPPORT => declared >= 1,
        // ADR-015: the chain states how many signatures an approval-evidence
        // block may carry; this build states how many it can aggregate and
        // verify. A chain above the local ceiling produces evidence this node
        // could never check.
        //
        // The only per-build limit left in this function, and reachable only from
        // acceptance because the parameter is literal-only (`PER_BUILD_LIMITED_IDS`
        // asserts that). It is also the ceiling `required_support` clamps to, which
        // is why the clamp is chain-determined rather than build-determined.
        parameter::MAX_AGGREGATED_SIGNATURES => {
            declared >= 1 && declared <= MAX_AGGREGATED_SIGNATURES as u64
        }
        // FR37: the denominator of the anti-capture rule.
        parameter::VOTE_SCALE => declared != 0,
        // The compile-time block buffer width above; the fixed header below,
        // since a limit that cannot admit a header admits no block at all and
        // every remaining-capacity computation against it underflows.
        parameter::BLOCK_SIZE_LIMIT => {
            declared > HEADER_SIZE as u64 && declared <= MAX_BLOCK_SIZE as u64
        }
        // A percentage.
        parameter::BLOCK_FILL_THRESHOLD_PERCENT => declared <= 100,
        // The compile-time active-chain capacity above; a window has to hold at
        // least one block below.
        parameter::ACTIVE_CHAIN_LENGTH => {
            declared >= 1 && declared <= SNAKE_CHAIN_LENGTH_MAX as u64
        }
        // The budget every evaluation is bounded by, and which acceptance itself
        // spends once per argument-less program. At zero every program silently
        // resolves to its default with no diagnostic anywhere; unbounded above, a
        // single content could hold the core for as long as it asked.
        parameter::VM_FUEL_LIMIT => declared >= 1 && declared <= VM_FUEL_LIMIT_MAX as u64,
        _ => true,
    };

    if within {
        Ok(())
    } else {
        Err(ChainConfigError::BoundViolation(id))
    }
}

#[cfg(test)]
mod tests;
