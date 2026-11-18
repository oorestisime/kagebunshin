# Security

## Reporting a vulnerability

Please report it privately through GitHub's
[private vulnerability reporting](https://github.com/oorestisime/kagebunshin/security/advisories/new),
not in a public issue. Include the version (`kagebunshin --version`), the
OS, and the steps to reproduce. Never include real secret values; a dummy
value that shows the leak is enough.

You should hear back within a week. Fixes go into the next release, with
an advisory once it is out.

## What counts

kagebunshin's scope is written down in
[docs/threat-model.md](docs/threat-model.md). In scope, for example:

- a value reaching a log, `status`, `diff`, the audit log or an error
  message when it should not;
- any caller getting a value marked sensitive without an approval in the
  app, or a mark removed without the store passphrase;
- a human-only action (`get`, `unlock`, store writes) done without the
  store passphrase;
- a remote caller getting anything while the endpoint is off or the
  daemon is locked, beyond its machine's grant, or through a request other
  than `run`, `status` and `diff`;
- a remote peer accepted without being identified, or the daemon
  listening on an address other than its tailnet address;
- a refusal, an approved hand-out or a remote request missing from the
  audit log (the threat model lists what it does not record);
- the store file, socket or audit log created with permissions others can
  read.

Out of scope are the limits the threat model already lists, such as a
local agent using your AWS profile directly, a same-user process reading
another process's environment, or masking missing an encoded value.

## Supported versions

Only the latest release.
