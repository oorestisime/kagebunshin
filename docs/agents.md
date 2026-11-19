# Coding agents

## Start the agent as usual

```sh
opencode
```

The agent runs `kagebunshin run -- <cmd>` whenever a command needs
secrets. Each `run` gets only the values that command needs (the keys
`.env.example` lists). Every caller gets the same policy, agent or not:
a command that needs values marked sensitive waits until you approve it in
the app with the store passphrase, or on your paired phone (it is refused if the app is not running and no phone is notified; in the tray counts as running),
and what only you may do asks for the store passphrase. Approving a command
trusts it: a script can print what it was given. Refusals and approvals are
recorded in the audit log.

## Start your checkouts

```sh
kagebunshin onboard ~/code/widget ~/code/blog
```

With one passphrase prompt, each checkout's `.env` goes into the local
store and each checkout without one gets a drafted project. A checkout of
several apps gets a project per app; before it asks for the passphrase it
lists each app and what it does for it, and `--exclude APP` leaves one
out, by its folder or its project's name:

```sh
kagebunshin onboard ~/code/shop --exclude apps/admin
```

An app left out gets no project and nothing of it is imported, and it
stays out when the checkout is set up again; `kagebunshin onboard` of
its own folder sets it up. It prints what is left in each, for you and
for the agent, and one line to paste into the agent in each checkout that
is not done:

```text
Set up kagebunshin here: run `kagebunshin next` and do what it says until it says done.
```

Your agent can do this for you. Open the app (`kagebunshin app`), name
the checkouts, and paste:

```text
Set up kagebunshin in ~/code/widget and ~/code/blog: run `kagebunshin next ~/code/widget ~/code/blog` and do what it says until it says done.
```

The agent runs `onboard` itself. It has no terminal to ask you at, so the
app's window asks instead: it lists each file, the project and environment
its values go to, and each key by name, never a value, and takes the store
passphrase once for all of them. Deny it, or leave it unanswered, and
nothing is imported. The files are kept; deleting them is yours to do.
With the app closed, `onboard` imports nothing (error `no_app`) and the
agent asks you to open it.

A secret that is in no file the agent asks you for the same way. It runs
`kagebunshin store set widget.dev API_KEY DB_PASSWORD`, which names keys
and no value, and the app's window has a hidden field for each key: type
the values and the store passphrase there, and Save writes them. A key
that has a value now is shown as one you would replace, and a field you
leave empty leaves that key as it was. The agent is told which keys were
set, never a value. Deny it, or leave it unanswered, and nothing is set.

It takes one `.env` file for each app by itself. Files with values under
other names (`.dev.env`, `production.env`, `.dev.vars`), in any folder of
the checkout, are named at the end with the command that imports each,
since nothing says which environment their values are for:

```sh
kagebunshin onboard --file ~/code/widget/production.env --env prod
```

That puts the file's values in the local store for the project of the app
the file is in, adding the environment when the project does not have it;
a value already there is replaced, and the output says which. In a
repository of several apps, a file outside every app's folder also needs
`--name PROJECT`. `--file` may repeat.

## Never wrap the agent in `run`

```sh
kagebunshin run -- opencode        # don't
```

That puts every value in the agent's own environment, where it can read
them and hand them to anything it starts, and the audit log only sees one
`run`. Start the agent on its own and let it call `run`.

## Teach the agent

`kagebunshin init --agent` prints instructions for the agent: what it must
never do (print values, use `get`, edit the TOML), how to
use `run`, `status` and `diff`, how to set up sources, and what to tell you
when something is refused. Put them where your agent reads them:

```sh
# OpenCode, as a skill
mkdir -p ~/.config/opencode/skills/kagebunshin
kagebunshin init --agent --skill > ~/.config/opencode/skills/kagebunshin/SKILL.md

# Anything that reads AGENTS.md
kagebunshin init --agent >> AGENTS.md
```

## Hooks

`kagebunshin hook install claude` adds two hooks to
`~/.claude/settings.json`, keeping everything else in it;
`kagebunshin hook install opencode` writes the plugin
`~/.config/opencode/plugins/kagebunshin.js`. `install.sh` runs them, next to
the skill, for each agent it finds, and `kagebunshin uninstall` takes them
out again. Both run `kagebunshin hook`:

- When a session starts in a registered project, the agent is told so, and
  to run commands that need secrets with `kagebunshin run`. If the daemon
  is not running or is locked, it is told that too, and that the human has
  to start it or run `kagebunshin unlock`. Until the default environment
  has every key and a `run --strict` command has succeeded with them, it is
  also told to run `kagebunshin next` and do what it says.
- When a session starts in a folder that is in no project but has a `.env`
  or `.env.example`, the agent is told kagebunshin is installed and how to
  start: run `kagebunshin next` and do what it says. If a `.env` has
  values, it is also told not to read it, and that they are moved in with
  your approval: `next` says how. A folder with neither gets nothing.
- When a session starts at the root of a repository of several apps, the
  agent is told which folders have a project each, or, when none has one
  yet, which apps there are, and to run `kagebunshin next`.
- Before a file is written, writing a real env file (`.env`, `.env.local`,
  but not `.env.example`) in a registered project is refused, pointing the
  agent at `run`. That covers the file-writing tools and shell commands
  that plainly write one: a `>` or `>>` redirect, or `cp`, `mv`, `tee`,
  `touch`, `ln` or `install` with an env file as the target, so
  `cp .env.example .env` is refused. Like output masking, this catches the
  usual accident, not a determined agent: `sh -c`, variables and the like
  are not looked into.

Nothing else is refused, and a hook that cannot tell (no config, not a git
checkout, no answer from the daemon within a second) stays out of the way.

## Letting the agent set up a project

Create the project yourself, or let the agent do it, and let the agent
add the sources:

```sh
kagebunshin project init widget --profile widget-dev
aws login --profile widget-dev
opencode
```

Then, for example:

> Set up kagebunshin for this repo. The dev secrets are in AWS Secrets
> Manager under the prefix `acme/dev/`, profile `widget-dev`, region
> `eu-west-1`. Use `kagebunshin list` to see the names, add the
> sources, check with `kagebunshin diff`, then run the tests with
> `kagebunshin run`.

The agent lists secret names (never values), adds sources with
`project add-source`, and checks with `diff`. `kagebunshin list --keys`
also shows the key names inside each AWS secret; the daemon reads the
values to find them and hands back only the names. Instead of adding
sources one at a time, the agent can write the whole project file and
run `kagebunshin project apply FILE --check`, which resolves it in a dry
run and reports what is set, missing, extra or conflicting, then
`kagebunshin project apply FILE` to install it whole.
`kagebunshin project draft` writes a first such file from the checkout
and the key names the providers list: an environment for each one a
deploy workflow lists secrets for, with those secrets in the workflow's
order, and what it could not decide as `# open:` comments that each carry
the commands to run;
`project draft --apply` installs it. An environment named `prod` or
`production` the agent marks sensitive itself (`kagebunshin mark env`),
which takes no passphrase; only you remove a mark, in the app. A source
that looks like production, or an environment named `rc`, makes the
environment wait for your decision: until you mark
it sensitive or acknowledge it is not production in the app
(`kagebunshin app`; it takes the store passphrase), its values are handed
out only with your approval there. A
source edit takes effect at the next command; a value changed at the
provider is fetched again by `kagebunshin sync`.

A new project with no sources reads the local store's `[<project>.dev]`
section, empty until you store values there. `status` and `diff` then
list the missing keys with the command to run, such as
`kagebunshin store set widget.dev API_KEY DB_PASSWORD`. Run in a terminal
it asks for the passphrase and then each value. The agent runs it too,
while the app is open: it has no terminal, so the app asks you for the
values and the passphrase.

Settings that are not secret (`PORT=3000`) the agent can set itself, with
`kagebunshin project set-var widget dev PORT 3000`: they go in the project
file, lose to any source that sets the same key, and are not masked. `diff`
suggests one when `.env.example` gives a missing key a value; the agent is
told to use it only when that value is real and not a placeholder. See
[project-files.md](project-files.md#plain-settings).

## What is left: `kagebunshin next`

`kagebunshin next` is the agent's checklist. It looks at the daemon, the
store, the project and its default environment (or `--env`), and prints
how far setup is, the one step for the agent with its command, and what
waits on you, with the sentence the agent should tell you:

```text
project widget, environment dev: 1 of 1 keys set, not yet proven
next (you): prove the setup: run the project's tests or its start command with its keys; pick the command
  kagebunshin run --strict -- COMMAND
```

Setup is done when every key is set and a `kagebunshin run --strict`
command exited 0 with the environment as it is now. The daemon keeps that
proof (the time and the program's name, never its arguments) beside its
audit log, and drops it when the environment's sources or plain settings
change. `status` shows it as `every key set; \`cargo\` ran with them on
14 Nov`.

An app with no `.env.example` gets every key of its environment on every
run, so there is nothing to count and nothing left out. Setup is done
without the file. Once it is done, `next` suggests it, and the agent
passes that on to you instead of writing it unasked:

```text
project widget, environment dev: done. 13 of 13 keys set; `npm` ran with them on 14 Nov. They come from aws_sm:widget/dev (13).
suggested, not needed: this app has no .env.example, so a command run here gets all 13 keys of the environment. `kagebunshin project example` writes one from the 4 keys kagebunshin finds its code reading, names only, and a command then gets those and no more.
```

`kagebunshin project example` writes `.env.example` in the project's
folder with the names its code reads, one `NAME=` to a line and no value.
It searches the text of the files git tracks or would, runs nothing and
opens no env file; [project-files.md](project-files.md#an-app-with-no-envexample)
says what it recognises. The list is a seed: the agent checks it against
the code, adds a key read another way and takes out a name that is no
secret. It never writes over a file (error `exists`), and writes none when
it finds no key (error `no_keys`): the file is then written by hand, one
`NAME=` to a line. From then on a command gets only the keys listed, and a
request that needs your approval names those keys, not the whole
environment. For an environment marked sensitive the suggestion is the
same; its keys are in the code, which the agent may read.

At done, `next` also says where the keys come from, so the agent's closing
summary is exact:

```text
project widget, environment dev: done. 4 of 4 keys set; `cargo` ran with them on 14 Nov. They come from aws_sm:acme/dev/widget (2), file:widget.dev (1), the project file (1).
```

`onboard`, which moves an env file's values into the local store, is the
agent's step while the app is open: it runs it and you approve the import
in the app's window with the store passphrase. With the app closed it is
yours: the agent asks you to open the app, or to run it in a terminal. It
names its folder in full, such as
`kagebunshin onboard /home/you/code/widget`, so it runs from any terminal.
`store set`, for the secrets no file has, goes the same way: the agent's
step while the app is open, after everything it can set by itself, and
yours while it is closed. `kagebunshin --json store set` then prints
`{"section", "set", "replaced", "left", "locked"}`: the keys you typed a
value for, those of them that had one before, and those you left empty.
Once setup is done, what is left for you is listed, for when you like: an
env file still in the folder, to delete, the files with values that were
not imported (`.dev.env`, `production.env` and the like), each with its
`kagebunshin onboard --file` command, and each other environment of the
project that looks like production and waits for your decision in the app.
The files not imported are yours from the start and never hold up done: a
file imported with `--file` and kept is not named again until it changes.
While the environment `next` looks at waits for that decision, the agent
gets no step for it, and typing its values is yours, at a terminal.

At the root of a repository of several apps, each its own project, `next`
says where each app stands and gives the step for the first one that has
one, with the folder to run it in:

```text
this repository has 2 apps, each its own project
  apps/web: in no kagebunshin project yet
  apps/worker: project widget-worker, environment dev: 2 of 2 keys set, not yet proven
next (you): in apps/worker: prove the setup: run the project's tests or its start command with its keys; pick the command
  cd apps/worker && kagebunshin run --strict -- COMMAND
waiting on the human; tell them:
  - Please open the kagebunshin app (`kagebunshin app`) and say when it is open: I then move the values of apps/web/.env into kagebunshin, and you approve it in the app's window with the store passphrase. Or run `kagebunshin onboard /home/you/code/widget` in a terminal yourself; it asks for the passphrase there.
```

`kagebunshin next DIR…` gives one plan for several checkouts: where each
stands, one `onboard` for all their env files, so you approve once, and
then each checkout's own step with the folder to run it in:

```text
2 checkouts
  /home/you/code/widget: project widget, environment dev: 2 of 2 keys set, not yet proven
  /home/you/code/blog: project blog, environment dev: done. 2 of 2 keys set; `npm` ran with them on 14 Nov. They come from file:blog.dev (2).
next (you): in /home/you/code/widget: prove the setup: run the project's tests or its start command with its keys; pick the command
  cd /home/you/code/widget && kagebunshin run --strict -- COMMAND
```

`kagebunshin --json next` prints one object:

```json
{"project":"widget","env":"dev","done":false,"keys":{"set":3,"wanted":4},
 "headline":"project widget, environment dev: 3 of 4 keys set",
 "step":{"who":"agent","what":"…","command":"kagebunshin project set-var widget dev PORT 3000","tell":null},
 "human":[{"what":"…","command":"kagebunshin store set widget.dev API_KEY","tell":"Please run `kagebunshin store set widget.dev API_KEY` in a terminal; …"}]}
```

`project`, `env` and `keys` are null before there is an environment to
count, at the root of a repository of several apps, with several
checkouts, and for an environment
marked sensitive, which an agent is not shown; `headline`, the first line
of the text form, says which. `step` is null when nothing is left for the
agent; each `command` may be null (a decision in the app has none). The fixes in `status` and
`diff` also carry `who` (`agent` or `human`), and `status --json` lists what
is left for you as `human`, in the same shape, when there is any.

## What the agent is refused

What needs the store passphrase (`get`, `unlock`, store writes other than
an `onboard` you approve in the app or a `store set` whose values you type
there, which are refused with `no_app` while the app is closed); `status` and `diff` of an environment marked sensitive; and any `run` that would
inject a sensitive key, unless you approve it in the app (the whole command
waits, not just that key). Each comes back with an error code, a hint, and
who can fix it: `agent` when the agent can run the command itself, `human`
with a `tell`, one sentence for the agent to pass on to you as it is, such
as "unlock kagebunshin: run `kagebunshin unlock` in a terminal". In text it
is the line `ask the human: ...`. A refusal that waits for you (locked,
sensitive, production-looking, not approved) exits 5. A request the app
asked about and that was not approved says how it ended (a person denied
it, or nobody answered in time) and what it asked for: after a denial, ask
the human before running it again; after a timeout, run it again once they
are at the screen.

With `--json`, an error is one line of
`{"code", "message", "hint", "who", "tell"}` on stderr and each warning one
line of `{"warning": "..."}`; stdout is unchanged.

These are rules for a cooperative agent, not a wall: it runs as your user.
See [threat-model.md](threat-model.md#one-policy-for-every-caller).
