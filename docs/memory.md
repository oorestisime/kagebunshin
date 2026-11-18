# Secret values in memory

What kagebunshin does to keep secret values out of swap, core dumps and
other processes, and the copies it cannot control.

## What it does

- **Locked pages.** Every `SecretValue` is copied into whole pages of its
  own, mapped privately, locked with `mlock` so they are never swapped out
  and, on Linux, excluded from core dumps with `MADV_DONTDUMP`. On drop they
  are zeroed, unlocked and unmapped. The `String` the value came from is
  zeroed once copied. One value per page because `mlock` does not count:
  unlocking one of two values that shared a page would unlock both.
- **Zeroed buffers.** IPC frames, values on the wire (`WireSecret`), the
  decrypted store plaintext, the masker's patterns and passphrases are
  `Zeroizing`: ordinary heap memory, zeroed on drop.
- **No dumps.** The daemon and the CLI set their soft `RLIMIT_CORE` to 0 at
  start, and on Linux `PR_SET_DUMPABLE` to 0. That also stops other
  processes of the same user from attaching a debugger or reading
  `/proc/<pid>/mem` and `environ`. The soft `RLIMIT_MEMLOCK` is raised to
  the hard limit.

## The budget

Each value takes at least one page (4 KiB, 16 KiB on Apple silicon) of
`RLIMIT_MEMLOCK`. Linux 5.16 and later default to 8 MiB, about 2,000 values
on 4 KiB pages; older kernels and some distributions default to 64 KiB,
about 16. Raise it with `LimitMEMLOCK=` in a systemd unit or in
`/etc/security/limits.conf`. macOS does not enforce the limit for `mlock`.

When a value cannot be locked:

- by default it stays on the heap, still zeroed on drop, and the daemon logs
  one warning;
- with `strict_memory = true` in `config.toml`, the daemon refuses instead:
  `unlock` fails if the local store's values cannot be locked, an
  environment whose values cannot be locked is not served or cached, and a
  store write that leaves a value unlocked locks the daemon (the write
  itself is already on disk).

The CLI does not read `strict_memory`. The values it holds (for `run`,
`get` and the masker) fall back to the heap without a warning; they live only
as long as the command.

## Copies kagebunshin does not control

Each of these holds a value in ordinary, unlocked memory for a while, and
none is zeroed when freed:

- **AWS SDK buffers.** The HTTP response body and the SDK's own copy of
  `SecretString` before kagebunshin takes it.
- **`serde_json`'s decode buffer.** Used for escapes when parsing an AWS
  secret's JSON and when decoding an IPC frame.
- **`age`'s decrypt buffer.** The chunks of the store plaintext as `age`
  decrypts them, before they reach the zeroed buffer.
- **`Command::env`.** `run` and `session` pass values to the child in its
  environment. The standard library copies them into the `execve`
  arguments, and the child's environment is then plain memory in the child,
  readable through `/proc/<pid>/environ` by the same user unless the child
  turns that off itself.

## What children inherit

The children of `run` and `session` inherit the soft `RLIMIT_CORE` of 0, so
they do not dump core either, which is what you want for a process with
values in its environment. The hard limit is left alone, so a child can raise
it again. `PR_SET_DUMPABLE` is reset by `execve`, so children can be debugged
as usual.
