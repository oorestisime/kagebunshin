# Working on Kagebunshin

House rules for anyone, human or agent, changing this repository. For how
coding agents *use* Kagebunshin, see [docs/agents.md](docs/agents.md).

## Rust

- **Return errors, don't panic, in the daemon.** A panic takes down every
  session. `unwrap`, `expect` and `print!`/`eprint!` are denied by Clippy
  outside tests and the CLI's output layer; if one is truly unreachable, use
  a scoped `#[expect(clippy::..., reason = "...")]` that says why.
- **Never put secret values in logs, `Debug` output or error messages.** Wrap
  values in `SecretValue`, keep its redacting `Debug`, and name the key, not
  its value, in errors. Tests use `test_support::Canary` to check this.
- **Put tests next to the code**, in a `#[cfg(test)] mod tests` (or a sibling
  `tests.rs`). `tests/` is for end-to-end tests of the binaries and socket.
- **Keep Kagebunshin generic.** No company-, team- or project-specific names,
  paths, accounts or defaults in code, docs or tests.

## Before every PR

Run these locally; all must pass:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

`--workspace` matters: `kagebunshin-app` is not a default member, so plain
`cargo clippy`/`cargo test` skip it. `cargo machete` should also stay clean.

CI runs fmt, clippy and the tests on Linux for every pull request, and
the tests on macOS once it is merged, but not the `e2e` crate, so the
local run above is still the gate.
