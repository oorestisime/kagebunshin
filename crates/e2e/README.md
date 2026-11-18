# The end-to-end suite

Each test builds a sandboxed machine (a fresh `HOME`, a real daemon, the real
`kagebunshin` and `kagebunshin-app` binaries, nothing of yours), runs commands
on it as the agent or the human would, and compares what was said, word for
word, with a snapshot in `tests/snapshots/`. No test needs an account
anywhere.

A test also fails when a value shows up where an agent reads, or in the
daemon's log: every value a sandbox holds has `CANARY` in it.

## Running it

    cargo test -p kagebunshin-e2e      # under two minutes

    scripts/e2e.sh                     # the same, against the AWS Emulator
    scripts/e2e.sh --test aws          # one file

`cargo test --workspace` runs it too. The tests build the workspace's
binaries themselves before running them. `scripts/e2e.sh` is the fuller run: do
it before a release and when you change how AWS is read.

When what kagebunshin says changes, a snapshot fails and shows the difference.
If the new wording is what you meant, accept it and commit the snapshot with
the change; the diff of `tests/snapshots/` is then what a reviewer reads to
see what an agent or a human is told differently.

    INSTA_UPDATE=always cargo test -p kagebunshin-e2e
    INSTA_UPDATE=always scripts/e2e.sh     # for the tests marked `ignore`

To look at what a failing test left behind (the daemon's and the app's logs,
the app's screenshots under `shots/`), keep its sandbox; the path is printed:

    KAGEBUNSHIN_E2E_KEEP=1 cargo test -p kagebunshin-e2e --test walk

## What is in it

| File | What it walks through |
| --- | --- |
| `tests/walk.rs` | The whole setup, from an empty machine to `next` saying done: several checkouts, a monorepo, `.env` files, hooks, production waiting for the human in the app. |
| `tests/aws.rs` | AWS doing more than handing over a value: hundreds of secrets, one it refuses, a binary one, one that changes and is deleted, logins that ran out. |
| `tests/proton.rs` | Proton Pass from `connect` to a revoked token. |

`tests/support/` is the sandbox and the walk; start a new test from
`tests/proton.rs`, the shortest.

## What stands in for each provider

**AWS** has two stand-ins, and every snapshot holds for both.

- By default, a small fake of Secrets Manager inside the test
  (`tests/support/aws.rs`). It needs nothing, and it checks nothing: any
  signature and any policy passes.
- The AWS Emulator, AWS's own, when
  `KAGEBUNSHIN_E2E_AWS_EMULATOR` names its binary. It checks request
  signatures, enforces resource policies, has binary secrets, deletion with a
  recovery window, and IAM Identity Center. Tests that need those are marked
  `ignore`. `scripts/e2e.sh` downloads one pinned release into
  `~/.cache/kagebunshin-e2e` (190 MB, 1 GB unpacked; Linux only), checks AWS's
  signature on it, and runs everything. Nothing is installed. To move to a
  newer release, change `VERSION` in the script.

**Proton Pass** is a fake `pass-cli`, the one the daemon's own tests use
(`kagebunshin::test_support::FakePassCli`), reached through
`KAGEBUNSHIN_PASS_CLI`.

## What a stand-in proves

The fake AWS and the fake `pass-cli` say what we believe each provider
answers. They prove that kagebunshin does the right thing with those
answers; they cannot prove the provider still answers that way. The AWS
Emulator is AWS's own word on it.
