# Roadmap

What is agreed and not built yet. Each entry says what and why.

## Before v1

What is left of v1 is release work:

- Test with a real agent locally, checking the three promises against
  the audit log.
- Proton Pass: see for real the error an expired `pass-cli` session
  gives, which is tested only against a fake `pass-cli` whose JSON
  follows Proton's documentation, and decide which `pass-cli` version to
  require (none is checked today). The rest ran for real, with `pass-cli`
  2.7.0: a bot on another Linux machine got a value from a real vault
  over the tailnet with its grant's token, and a key marked sensitive
  waited for approval in the app; each request is in the audit log with
  the machine that asked, and no token. `pass-cli` shows a token's expiry
  only in human-readable output, so `connect proton --expires` is typed
  by hand until it has a machine-readable form.
- macOS: build and test it again. CI was off from 11 November 2026 until
  the repository went public, and nothing compiled there in between; the
  Release workflow builds the macOS tarball once it passes.
- Signed and notarized macOS builds; a Homebrew tap from
  `packaging/homebrew/kagebunshin.rb`; `cargo install` from crates.io,
  which `publish = false` blocks today.
- Choose the version number for v1 (today `0.0.1-alpha.10`), bump it and
  tag; the release workflow refuses a tag that does not match it.

## After v1

### Vercel

A `vercel` provider was written and taken out before v1: it had only run
against hand-written answers, never a real team, and Vercel does not
return the value of a variable marked sensitive there, which limits what
a provider can hand over. Bring it back once someone needs it, tested
against a real account.

### More password managers: 1Password and Bitwarden

Many teams share secrets in a password manager, and each person then
pastes them into a `.env`. Reading them from the manager is what keeps
them out of one. Proton Pass is the first; 1Password and Bitwarden are
next, each through its own command-line tool, as Proton Pass is through
`pass-cli`. Open for each: which items count as a key, and where the
environment variable's name comes from.

### Caller identity from `SO_PEERPIDFD`

Today the daemon identifies a caller by peer credentials plus the pid's
start time, which a reused pid can fool. On Linux 6.5 and later,
`SO_PEERPIDFD` gives a pidfd for the peer that cannot be reused. macOS has no
equivalent; it keeps the start-time check.

### Smaller items

- Overwriting an existing project with `import`, behind step-up.
- `project remove-source` and `move-source` in the CLI; today only the app
  has them.
- Lock on sleep and suspend; record idle-timeout locks in the audit log.
- A static (musl) Linux build; `.deb`.
- Config an agent cannot write (another user, or signed), so a local agent
  cannot repoint an environment that is not marked at new sources.
