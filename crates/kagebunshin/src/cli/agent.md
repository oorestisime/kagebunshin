# kagebunshin: secrets for this repository

kagebunshin is a local secrets broker. A daemon holds the secret values.
You never see them: `kagebunshin run` puts them in the environment of the
command it runs. Some things are refused to you on purpose: a value marked
sensitive, and anything that needs the human's passphrase.

## Never

- Print, echo, log, write to a file or paste a secret value, and never
  run commands meant to reveal one (`env`, `printenv`, `echo $DB_PASSWORD`,
  `cat` of a generated `.env`). `run` masks values in piped output; do not
  try to get around that.
- Use `kagebunshin get`. It is for humans and needs their passphrase.
- Edit the TOML under `~/.config/kagebunshin/` by hand. Use the commands
  `kagebunshin next` gives.
- Try to work around a refusal. Tell the human what was refused and the
  exact command they can run themselves.

## Using secrets

    kagebunshin status            # project, environment, where each key comes from (no values)
    kagebunshin diff              # keys in .env.example that no source sets (--verbose lists every key)
    kagebunshin run -- npm test   # run a command with the secrets in its environment

Run from inside the repository; in a repository with one project per app,
from inside the app's folder, or anywhere in the checkout with
`--project <name>`. `run` injects the keys `.env.example` lists (all keys
when there is none, with a warning); add `--strict` to fail on a missing
one. Prefer `kagebunshin run -- <command>` over writing a `.env` file;
where kagebunshin's hooks are installed, writing one in a registered
project is refused.

## Setting up, and whenever something is missing

Run `kagebunshin next` and do what it says. Run it again after each step,
until it says `done`. It looks at the daemon, this checkout and its
project, and prints what is left:

- `next (you):` one step for you, with its command. Run that command, then
  run `kagebunshin next` again. Do not plan further ahead than it does.
- `waiting on the human; tell them:` sentences for the human. Pass each on
  to them word for word, once. If there is also a step for you, go on with
  it; if not, stop and wait for them.
- `done`: every key is set, and a command ran with them. Tell the human
  in a sentence or two what you added (sources, plain settings) and what
  it still lists for them.
- `suggested, not needed:` a line under `done`, for an app with no
  `.env.example`: every command there gets every key of its environment,
  and the file would narrow that. Setup is done without it. Pass it on to
  the human once, in your summary, and write the file only if they ask.
  `kagebunshin project example` writes it from the names it finds the code
  reading; it never reads a value. Then check it against the code: add a
  key the app reads another way, take out a name that is no secret or that
  the app runs without.

Three of its steps leave something to you:

- **Proving the setup.** It prints `kagebunshin run --strict -- COMMAND`.
  Put in a command the project already has, its tests or its start
  command, and run it. Exit 0 is the proof.
- **A plain setting** (`kagebunshin project set-var ... PORT 3000`). Run it
  only when `.env.example`'s value is the real setting, not a placeholder
  such as `changeme`, and never for a secret: it is kept in plain text and
  not masked. Otherwise tell the human the key needs a value.
- **A key no source sets.** It prints a `kagebunshin list --keys` command
  that names each secret and the keys inside it, never values. Add the
  secret that holds the key with the `kagebunshin project add-source`
  command it gives. If none does, run the `--provider file` command it
  gives instead: the next `kagebunshin next` asks the human for the value.
  A secret you picked by its name alone, as a plain string has no key
  names to go by, is a guess: say so when you tell the human what you
  added.

In a repository with several apps, each app is its own project. At the
repository's root, `kagebunshin next` goes through them and gives each
step with the folder to run it in (`cd apps/web && ...`); in an app's
folder it is about that app.

To change a project later (another environment, another source, a
profile), `kagebunshin project --help` lists the commands and
`kagebunshin project show <project>` prints what is there. A source edit
takes effect at the next command. A value changed at the provider does
not: `kagebunshin sync` fetches again, and needs no passphrase.

## Refused, and what to tell the human

An error says who can fix it. With `who: agent`, run the hint's command
yourself. With `who: human` (in text, a line `ask the human: ...`), pass
the `tell` sentence on to them as it is and wait; do not try to do it
yourself. A refusal that waits for a human exits 5.

- **The daemon is locked** (`locked`): ask them to unlock it, in the app or
  with `kagebunshin unlock`.
- **Credentials are missing or expired** for an AWS profile: ask them to log
  in to the profile the error names, in the app or with the
  `aws login --profile X` it names, then `kagebunshin sync`.
- **A sensitive environment, secret or key** (`sensitive_env`): it is off
  limits unless the human approves that one command in the app, which must
  be open; `run` then waits for them. Do not ask for it to be
  unmarked.
- **Not approved** (`not_approved`): the human denied the command in the
  app, or did not answer in time. Do not retry it without asking them.
- **Marking sensitive:** you add a mark yourself, with no passphrase:
  `kagebunshin mark env PROJECT ENV`, `kagebunshin mark secret PROVIDER
  NAME` or `kagebunshin mark key SECTION KEY`. Mark what is production.
  Marking too much costs the human an approval; marking too little hands
  out production values. No command removes a mark or acknowledges an
  environment as not production: only the human does that, in the app,
  with the store passphrase.
- **An environment named `prod` or `production`** is yours to mark:
  `next` gives you the `kagebunshin mark env` step, and setup is not done
  until it is marked.
- **An environment that only looks like production** (named `rc`, or a
  `prod`, `production` or `rc` segment in a source's name or its AWS
  profile, or a configured pattern) waits for a human decision. Until
  then it is refused like a marked one (`sensitive_env`), or waits for
  approval in the app, and `next` gives you no step for it: the decision
  comes first. Tell the human to open the app (`kagebunshin app`) and
  either mark it sensitive or acknowledge it is not production. If they
  tell you it is production, mark it yourself. Do not ask them to
  acknowledge it for you if it is production.
- **Anything that asks for a passphrase at a terminal** (`get`, `unlock`,
  `store unset`, `store clear`): ask the human to run it.
- **A `.env` file with values:** do not read it. While its values are not
  in kagebunshin, `kagebunshin next` says how they get in. With the app
  open, `kagebunshin onboard` is your step: tell the human it waits for
  them to approve the import in the kagebunshin app, where they type the
  store passphrase, then run it. With the app closed it fails with
  `no_app`, and `next` gives the sentence that asks the human to open the
  app, or to run it in a terminal. If the human denies it, ask before
  running it again. Once the values are in, `next` says nothing of the
  file until setup is done, then lists it for the human to delete; do not
  delete it yourself.
- **Several checkouts:** `kagebunshin next DIR…` gives one plan for them
  all, with one `onboard` for every env file among them, so the human
  approves once.
- **An app the human does not want set up:** `kagebunshin onboard DIR
  --exclude APP`, by its folder or its project's name. It gets no project,
  nothing of it is imported, and `next` no longer waits for it.
- **A project to take away:** `kagebunshin project remove NAME`. Its
  output says which values are still in the local store and gives the
  sentence to pass on: `kagebunshin store clear NAME` asks for the
  passphrase, so it is the human's to run.
- **Keys only a human can type:** `kagebunshin next` gives the
  `kagebunshin store set` command, which names keys and never a value.
  With the app open it is your step: tell the human it waits for them to
  type each value, and the store passphrase, in the kagebunshin app, then
  run it. You are told which keys were set, which had a value before and
  which the human left empty, never a value. With the app closed it fails
  with `no_app`, and `next` gives the sentence that asks the human to run
  it in a terminal, or to open the app. If the human denies it, ask
  before running it again. Never pass a value as an argument, never pipe
  one in, and never ask the human to tell you one.

Every command takes `--json`; errors then come as one JSON object on
stderr with `code`, `message`, `hint`, `who` (`"agent"`, `"human"` or
`null`) and `tell` (what to ask the human, or `null`), and each warning
as one line of `{"warning": "..."}` on stderr. stdout, and a `run`
command's own output, stay as they are.
