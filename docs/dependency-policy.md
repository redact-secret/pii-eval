# Toolchain, MSRV and dependency policy

Status: implemented for the bootstrap workspace (all five crates have zero
third-party dependencies). Rules below govern future additions.

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
- The MSRV is valid only for the current dependency set (none). Adding or
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
   `crates/pii-eval-cli/tests/dependency_policy.rs` (currently empty); a name
   outside that list fails the test, as does a name containing a forbidden
   fragment (`tokio`, `reqwest`, `hyper`, `libc`, ...). The test uses
   `cargo tree` offline and runs under `cargo test --workspace --locked`.
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
| (none) | | | | |
