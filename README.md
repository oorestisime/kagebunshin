<p align="center">
  <img src="packaging/icons/kagebunshin.svg" width="72" alt="">
</p>

# kagebunshin

**Your coding agent runs your code with its secrets. It never has to see
one.**

kagebunshin is a local secrets broker for Linux and macOS. Secrets stay
where your team already keeps them: AWS Secrets Manager, a password
manager. When your agent runs a test or a dev server, that
command gets them in its environment. The agent knows they are provided.
It does not know what they are.

```console
$ git worktree add ../widget-fix && cd ../widget-fix
$ kagebunshin run -- npm test      # nothing to copy: the secrets are there
```

And what an agent gets back when a command it runs prints one:

```console
$ kagebunshin run -- sh -c 'echo "key is $API_KEY"'
key is <redacted:API_KEY>
```

## Why

I work with coding agents all day. They make worktrees, start new projects
and run my tests, and all of that needs secrets. I did not want to copy
`.env` files around for them, and I did not want my secrets in a
transcript or in a model's reasoning. An agent does not need to know a
secret, only that it is there.

- **Nothing to copy.** A project is known by its git remote, not by a
  file in a folder. A new worktree or a new clone has its secrets at once.
- **Nothing in the context.** There is no `.env` in the checkout to read
  or search. The agent sees the names of the keys and where each comes
  from, never a value, and values are masked in the output of what it
  runs.
- **From where the team keeps them.** Most teams share secrets in a
  password manager or a cloud secrets store, and then everyone pastes them
  into a `.env` anyway. kagebunshin reads them from there instead: AWS
  Secrets Manager and Proton Pass today, 1Password and Bitwarden
  planned. What lives nowhere else goes in a local encrypted store.
- **The agent does the work.** It sets a project up from one pasted line
  and runs everything through kagebunshin from then on. You are asked only
  for what shows a human is there: a passphrase, an approval.
- **Production waits for you.** What is marked sensitive, an agent cannot
  get by itself. The command waits while the app shows you what asks for
  which keys, and you approve that one request. Every refusal and every
  hand-out of a marked value goes in an audit log, by name.

<p align="center">
  <img src="docs/img/approval.png" width="760"
       alt="The app asks before a command gets a value marked sensitive: it shows the command, the key it wants, who asks and why.">
</p>

## Get started

**1. Install.**

```sh
curl -fsSLO https://raw.githubusercontent.com/oorestisime/kagebunshin/main/packaging/install.sh
sh install.sh
```

It asks you to choose a passphrase for the local store, starts the daemon,
gives OpenCode and Claude Code the kagebunshin skill and hooks when it
finds them, and on Linux puts the app in the tray.

**2. Paste this into your agent**, in a project's checkout:

```text
Set up kagebunshin here: run `kagebunshin next` and do what it says until it says done.
```

Or name several checkouts at once:

```text
Set up kagebunshin in ~/code/widget and ~/code/blog: run `kagebunshin next ~/code/widget ~/code/blog` and do what it says until it says done.
```

The agent moves each `.env` into the encrypted store, which you approve
once in the app, by key name. A secret that is in no file you type into
the app when the agent asks for it, never into the chat. It drafts the
project from the checkout and the providers you use, proves it by running
your tests, and tells you what is left for you, such as the env files to
delete.

<p align="center">
  <img src="docs/img/approval-import.png" width="760"
       alt="The app lists the env files an agent asks to import, where each goes and its keys by name, and takes the passphrase once.">
</p>

**3. That is it.** In a worktree or another clone of that project there is
nothing to do. In a new project, paste the same line; where the hooks are
installed and the folder has a `.env` or a `.env.example`, the agent is
told to run it without you.

Another agent learns the commands from `kagebunshin init --agent`; see
[docs/agents.md](docs/agents.md#teach-the-agent). To do the setup yourself,
see [docs/manual-setup.md](docs/manual-setup.md).

## Day to day

| The agent | You |
|---|---|
| `kagebunshin run -- npm test`: a command, with its secrets | `kagebunshin unlock`, after a reboot or the idle timeout |
| `kagebunshin status`: which keys are set and where from, never a value | Approve, in the app, a request for something marked sensitive |
| `kagebunshin next`: what is left to set up, and whose step it is | `kagebunshin app`: keys by environment, sources, marks, the audit log |
| Marks what is production as sensitive | The only one who can remove a mark |

Start your agent as usual, not with `run`: that would put every value in
the agent's own environment. See [docs/agents.md](docs/agents.md) for the
rest, and [docs/app.md](docs/app.md) for the app and its tray.

Agents on other machines can ask too, over an endpoint on your tailnet
that is off by default and where each machine needs a grant and its
token. See
[docs/config.md](docs/config.md#the-remote-endpoint).

## What it does not do

**Scoped, audited delivery, not invisibility.** kagebunshin decides which
values reach which command and writes the decisions down. It does not make
a value invisible to code that has it: a command that `run` starts can
print its own environment, and approving a command trusts it. Masking
covers the piped output of `run` and catches the accident, a value in a
log line or a stack trace, not a determined reader.

On your own machine the boundary is soft: an agent runs as you and can use
your AWS profile without kagebunshin, so give agent-facing environments a
profile that cannot read production. For a boundary that holds, run the
agent on another machine and give it the remote endpoint. See
[docs/threat-model.md](docs/threat-model.md) for exactly what is and is not
protected.

## Status

Alpha; the latest build is v0.0.1-alpha.10. It has binaries for Linux
x86_64 and aarch64 (glibc 2.35 or later) and for macOS arm64. The macOS
binaries are unsigned, and no one has run them outside CI, which builds
and tests them: expect rough edges there.

AWS Secrets Manager and the local store are in daily use. Proton Pass
has handed values from a real vault to a bot on another machine, through
the remote endpoint; that is one run, not daily use yet. The app is
experimental: its UI library is pinned to a
prerelease commit.

## Documentation

- [docs/install.md](docs/install.md): install, upgrade, uninstall, from
  source
- [docs/agents.md](docs/agents.md): running coding agents with
  kagebunshin, and what `kagebunshin next` does
- [docs/manual-setup.md](docs/manual-setup.md): the same setup, by hand
- [docs/app.md](docs/app.md): the app, the tray and approvals
- [docs/project-files.md](docs/project-files.md): project mapping files,
  sources and sensitivity
- [docs/config.md](docs/config.md): `config.toml`, directories, environment
  variables, the service
- [docs/threat-model.md](docs/threat-model.md): what is protected, from
  whom, and the known gaps
- [docs/memory.md](docs/memory.md): how values are kept in memory
- [docs/roadmap.md](docs/roadmap.md): what is agreed and not built yet
- [SECURITY.md](SECURITY.md): reporting a vulnerability

License: MIT.
