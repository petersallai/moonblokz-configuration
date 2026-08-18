# moonblokz-configuration

Chain-configuration module for MoonBlokz — the parameter registry, the code-baked defaults, the resolution model, content acceptance and the FR8 commitment state (FR56).

A MoonBlokz chain must run with parameters that are identical on every node: a divergence in these values is a divergence in validation outcome. This crate owns that agreement, and the blockchain consumes the result through per-parameter accessors without ever interpreting a configuration key itself.

- `no_std`, no-alloc, embassy-free. The dependency-graph gate (`cargo tree -e normal | grep -iE 'embassy|alloc'`) is empty, which is what keeps `moonblokz-blockchain` host-testable without an async runtime.
- Direct dependencies: `moonblokz-vm` (bytecode execution), `moonblokz-chain-types` (the payload envelope), `moonblokz-crypto` (signature width, aggregation ceiling). The crypto backend is not pinned here — it is forwarded from the top of the graph.
- No `unsafe`, so no Miri obligation.
- Authority: `moonblokz-info/moonblokz-configuration-specification.md`.

## Shape

```rust
let mut module = ChainConfiguration::new(NoopConfigChangeSink);
module.load_tentative(chain_config_block.payload())?;   // accepts, then notifies

if let Some(config) = module.active_configuration() {
    let interval = config.inter_block_interval_ms();
    let price = config.registration_price(registered_nodes);
}

module.promote_durable()?;                               // set-once, FR8
```

- **`ChainConfiguration<Sink>`** — one retained `MAX_PAYLOAD_SIZE` buffer plus a commitment flag. Tentative and durable content are never two different values at once: promotion flips the flag over the same bytes.
- **`ActiveConfig<'_>`** — the accessor surface, and the only way to read a value. It **borrows** the module, which makes FR56's no-caching rule structural: the handle cannot outlive the invocation that acquired it, nor be held across a state change. Availability is decided once, at acquisition, so `None` is answered per handle rather than per accessor.
- **`accept_content`** — framing, registry conformance and the structural bounds, on the raw declared values, before anything is loaded. This is the only place an out-of-range declared value is still visible: past a narrowing accessor it cannot be told from a legal one.
- **`ConfigChangeSink`** — a mandatory generic, so the no-op implementation optimises away and no runtime branch is paid per change. The transport (the firmware-side `Watch` carrying the radio snapshot) stays on the node side, which is what preserves the dependency gate.

## Correctness properties

- **The accessor surface is total.** Resolution runs override → code-baked default → code-baked fallback literal, and the last tier is a constant, so every accessor on an obtained handle returns a value. A program that traps, exhausts its fuel or names an unresolvable parameter is not an error the caller sees — it is a tier that failed.
- **Each tier that needs a budget gets a fresh one.** If a lower tier inherited an exhausted budget, then whenever exhaustion was the failure cause the tier below could never run. Sharing happens along the other axis: a nested `GETPARAM` draws from the budget of the invocation that started it, so a program cannot evade the bound by composing sub-evaluations.
- **Unknown keys are rejected, not skipped.** A node substituting its own default for a parameter it does not know would validate against different values than the rest of the network — a consensus split that produces no error anywhere. The consequence is deliberate: a chain's configuration content defines the minimum firmware capability required to participate, and a node older than a key the chain uses stays in collecting state. The rejection is distinguishable (`chain-config-unknown-key`, carrying the key byte) so the diagnosis reads *the node is out of date*.
- **Narrowing is by saturation**, consistent with the VM's arithmetic. A parameter whose bound must hold for this node to *represent* the chain is not left to saturation: it is literal-only, so acceptance checks its declared value.
- **Acceptance runs no program.** A program's result is only checkable ahead of time when it takes no arguments, so such a pass is partial by construction and grows more partial as the registry gains argument-taking parameters. A misbehaving program is covered completely by the resolution model instead — trap or exhausted budget, tier fails, fall through to the default and then the fallback literal, identically on every node. One total mechanism, not a partial one in front of it.
- **The execution budget is downward-only.** A chain may declare a `vm_fuel_limit` at or below the code-baked default, never above it: the default is the one value grounded in a timing estimate, so a higher ceiling would be a bound no measurement supports. Acceptance also checks the declared limit *before* spending it, since it pays that budget once per argument-less program.
- **The registry is permanent wire format.** Identifiers are allocated densely from 1 and are never reused or renumbered: FR7 requires the content signature to be invariant for the chain's lifetime and reproduced byte-identically in every FR49 replay block. **So are the defaults**, for a less obvious reason: a chain that omits a parameter validates against this build's default for it, so two firmware versions whose default tables differ by one value validate the same chain differently, with no error on either side. Changing a default is a consensus-breaking change, not a tuning decision.

## What is deliberately not here

- **Storage.** The blockchain owns the storage handle and performs every storage call, passing content bytes in both directions. This keeps the timing of the durable commit where the decision that triggers it lives, and avoids two owners of one `&mut` storage handle in a no-alloc, single-threaded design.
- **Signature verification.** The FR7 content-signature check is an FR9 Tier-1 trust-anchor check that runs in the blockchain, over the envelope `moonblokz-chain-types` frames.
- **Transport.** No `embassy-sync`, no snapshot publication.
- **The commitment lifecycle.** *When* to load tentatively, compare, promote or discard is the blockchain's decision; this crate holds the state those decisions move through.

## Tooling

`tools/config-encoder` is a separate `std` package — separation at the package level rather than by feature flag, because Cargo unifies features per package and a `std` tool sharing this one could pull `std` into the library's own build. It turns parameter overrides (literal values, and assembly source where a parameter may be referenced as `@name`) into signed configuration content, applying the same framing and acceptance checks the runtime does — no more and no less, so what the tool accepts is what the network accepts.

```
config-encoder INPUT.cfg --key KEY.hex [-o OUTPUT.bin]
```

Implementation tracked story-by-story in `_bmad-output/implementation-artifacts/sprint-status.yaml`.
