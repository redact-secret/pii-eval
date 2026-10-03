# Toolchain, MSRV and dependency policy

Status: implemented. Since P2 `pii-eval-contracts` has third-party
dependencies (table at the end); since P6 `pii-eval-adapters` also uses
`serde_json` (see "Adapters, shims and Node in CI"); the other crates have
none. Rules below govern future additions.

## Toolchain and MSRV

- Development and CI toolchain: Rust **1.98.1**, pinned in `rust-toolchain.toml`
  (`rustfmt` and `clippy` components, minimal profile). Bumping it is an
  explicit commit, not an incidental update.
- Edition **2024**, resolver 3.
- MSRV: **1.85** (`workspace.package.rust-version`). Determination, run on
  2026-10-02 against the committed `Cargo.lock`:
  - `cargo +1.84.1 build --workspace --locked` fails: edition 2024 is not
    stabilized in that cargo.
  - `cargo +1.85.0 test --workspace --locked` passes (all tests).
  - 1.85.0 is the first release that stabilizes edition 2024, so it is the floor
    for this workspace regardless of code.
- The MSRV is valid only for the current dependency set (re-verified at P2, see the table). Adding or
  upgrading a dependency requires re-running the MSRV test (the `msrv` CI job
  does this) and either keeping 1.85 or recording the new floor and why.
- MSRV is a build-compatibility statement for this repository, not a
  compatibility promise to consumers (crates are `publish = false`).

## Lints

`[workspace.lints]` sets `unsafe_code = "forbid"` and clippy `all` as warnings;
CI runs clippy with `-D warnings`. Every crate opts in with
`[lints] workspace = true`. Changing the unsafe rule requires an ADR and a
measured need (CONVENTIONS.md).

## Dependency rules

1. Default is no third-party dependency. Each addition needs a stated need
   that std cannot meet, in the PR description and in the table below.
2. Versions are exact-resolvable through the committed `Cargo.lock`; CI uses
   `--locked`. Prefer exact pins (`=x.y.z`) for crates that affect semantic
   output or serialization (JSON, hashing, numerics).
3. `pii-eval-contracts` and `pii-eval-kernel` must not depend, directly or
   transitively through normal dependencies, on process-spawning, networking,
   filesystem-walking or credential/Git crates, nor on `pii-eval-adapters`,
   `pii-eval-cli` or `pii-eval-compat`. Third-party crates they may use are
   listed in `ALLOWED_THIRD_PARTY` in
   `crates/pii-eval-cli/tests/dependency_policy.rs`; a name
   outside that list fails the test, as does a name containing a forbidden
   fragment (`tokio`, `reqwest`, `hyper`, `libc`, ...). The test uses
   `cargo tree` (`--locked`, all targets; it may fetch crate metadata from crates.io, which is already allowed) and runs under `cargo test --workspace --locked`.
4. `pii-eval-compat` is reachable only from tests of the CLI crate (a
   dev-dependency); no production crate may depend on it. It is deleted by
   removing the crate, its workspace entries and one smoke assertion.
5. Dependency additions and updates arrive in their own PR. Dependabot opens
   weekly `cargo` and `github-actions` PRs; they follow the same review.
6. GitHub Actions are pinned by full commit SHA with a version comment. The
   workflow requests `permissions: contents: read`, uses no secrets and
   performs no benchmark or scanner checkout.
7. Scanner packages and binaries are not workspace dependencies. Scanner
   shims and pins are introduced with the adapter work (P6) under SECURITY.md
   controls (digest verification, reviewed installation).

## Test-only code and property tests (P3)

P3 added no third-party dependency, normal or dev. Property tests in
`pii-eval-kernel` and `pii-eval-compat` use a 10-line SplitMix64 generator with
fixed seeds, written in the test files. `proptest` was considered and not
added: it brings a `rand` family closure, shrinking machinery and per-version
MSRV risk to this repository's exact-lock policy, and the properties here
(permutation invariance, offset round-trip, no panic on arbitrary bytes) do not
need shrinking because the generator is deterministic and a failure message
carries the iteration number. Revisit if a property needs shrinking; the
dependency would then be a dev-dependency of the kernel, justified in the table
above, the guard (which inspects normal and build edges only) would be
unaffected, and the MSRV job would have to pass.

`pii-eval-compat` depends on `pii-eval-kernel` as a dev-dependency, so legacy
and canonical outcomes can be compared on the same vectors. The kernel and
contracts still do not reach compat (checked by `dependency_policy.rs`).

## Adapters, shims and Node in CI (P6)

`pii-eval-adapters` now depends on `pii-eval-contracts`, `pii-eval-kernel`
(offset translation) and `serde_json` (strict parsing of shim output and
construction of the Rust-to-shim messages). `serde_json` is the version already
reviewed above, with the same feature set; the crate adds no third-party crate
to the lockfile, only dependency edges. Process execution uses `std::process`
and `std::thread` only: an async runtime, HTTP client or process helper crate
was not needed and stays forbidden, and
`adapters_use_only_the_reviewed_crates_and_std_for_processes` in
`crates/pii-eval-cli/tests/dependency_policy.rs` checks the adapters' closure
against the same allowlist and forbidden fragments. The kernel and contracts
rules (3 above) are unchanged.

Scanner packages remain outside the workspace (rule 7). The shim
`crates/pii-eval-adapters/shims/node/redact-secret-core.mjs` has no npm
dependency: it uses only `node:path` and `node:url` and imports the scanner by
absolute file URL from a path the adapter verified by digest. Test fakes under
`crates/pii-eval-adapters/tests/fixtures/` are inert and installed from nothing.
A real scanner package is only ever installed by a person into a scratch
directory outside the repository (`npm install --ignore-scripts`, integrity
compared with the oracle lockfile), for the opt-in test.

CI sets up Node 22 with `actions/setup-node`, pinned by full commit SHA like the
other actions, and sets `PII_EVAL_REQUIRE_NODE=1` so that adapter tests fail
rather than skip when Node is missing. No `npm` command runs in CI.

MSRV re-verified after these changes on 2026-10-02:
`cargo +1.85.0 test --workspace --locked` passes; the floor stays 1.85.

## Accounting and statistics (P4)

P4 added no third-party dependency, normal or dev. The Wilson endpoint needs
integer square root and division wider than `u128`, which is a 150-line private
512-bit unsigned integer in `pii-eval-kernel` (`bigint.rs`, checked operations,
unit-tested); a big-number crate was not added because the guard keeps the pure
crates to a minimal reviewed closure and the needed operations are few. The
independent Wilson reference is a Python script (`tests/vectors/wilson_reference.py`,
standard library `decimal` only, not run in CI); its output is committed as a
Rust table. MSRV was re-run for this change.

## Optional checks

`deny.toml` configures `cargo-deny` bans (process/network crates), sources and
licenses. It is verified locally with
`cargo deny --locked check bans licenses sources` (cargo-deny 0.20.2 on the
bootstrap machine). It is not a CI gate yet because CI would have to install
the tool; running `advisories` needs a network fetch of the RustSec database
and is outside the current network allowance. Both are proposed follow-ups.

## Reviewed third-party dependencies

| Crate | Used by | Why | Version | Reviewed |
| --- | --- | --- | --- | --- |
| `serde` (with `derive`) | contracts | Typed (de)serialization of every contract; the derive gives closed, exhaustive types. No std alternative. | =1.0.229 | P2; no I/O, no process or network code |
| `serde_json` | contracts, adapters | JSON parsing and value model for strict parsing, canonical form and schema output. Pinned exactly: parsing and number handling are semantic. `arbitrary_precision` and `preserve_order` are not enabled; the canonical writer sorts keys itself. | =1.0.151 | P2 |
| `schemars` | contracts | Deterministic JSON Schema generation from the same types, so schemas cannot drift from code (drift test). Pinned exactly: output is committed. Derive and std features only. | =1.2.2 | P2 |
| `sha2` | contracts | SHA-256 for the semantic digest and input identities; a reviewed RustCrypto implementation is preferred over hand-rolled hashing. Pinned exactly. `alloc` feature only. | =0.11.0 | P2 |

Transitive crates (all in `ALLOWED_THIRD_PARTY` in the guard): `serde_core`,
`serde_derive`, `serde_derive_internals`, `schemars_derive`, `syn`, `quote`,
`proc-macro2`, `unicode-ident`, `ref-cast`, `ref-cast-impl`, `dyn-clone`,
`itoa`, `memchr`, `zmij`, `digest`, `block-buffer`, `crypto-common`,
`hybrid-array`, `typenum`, `cfg-if`, `cpufeatures` and `libc`.

`libc` matches a forbidden fragment and is a reviewed exception: it is reached
only through `cpufeatures` (CPU feature detection used by `sha2`). The guard
(`FRAGMENT_EXCEPTIONS`) asserts that `cpufeatures` is its only direct
dependent in each pure crate's graph, and the other fragments stay forbidden.
No crate in the closure spawns processes or opens sockets. Hand-written SHA-256
was considered and rejected to avoid maintaining cryptographic code.

MSRV re-verified after these additions on 2026-10-02:
`cargo +1.85.0 test --workspace --locked` passes; the floor stays 1.85
(`sha2` 0.11, `serde_json` 1.0.151, `schemars` 1.2.2 declare 1.85, 1.71, 1.74).
