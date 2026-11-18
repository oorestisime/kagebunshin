# Setting up by hand

Your agent can do all of this from one pasted line; see the
[README](../README.md#get-started) and [agents.md](agents.md). This is the
same setup, typed yourself.

In a git checkout of the project, `widget` here, whose dev secrets live in
AWS Secrets Manager under `acme/dev/` with an SSO profile `widget-dev`:

```sh
# 1. Once per user: the config directory, the local store (you choose its
#    passphrase), and the daemon as a user service (systemd or launchd),
#    started now and at login, and unlocked. On Linux, also the app in
#    the launcher and in the tray, now and at each login.
kagebunshin setup

# 2. The project, found later by this checkout's git remote. No passphrase.
kagebunshin project init widget --profile widget-dev
kagebunshin project add-source widget dev --provider aws_sm --prefix acme/dev/ --region eu-west-1

#    Or let kagebunshin start each checkout for you, several at once (none
#    given: this folder). A checkout with a .env gets a project whose dev
#    environment reads the local store, with the file's values put there;
#    one without is drafted from its files and the providers. It asks for
#    the passphrase once, never prints a value, says what is left for you
#    and for your agent, and offers to delete the imported files. Your
#    agent can run it too: you then approve the import in the app.
kagebunshin onboard ~/code/widget ~/code/blog

#    An env file under another name (.dev.env, production.env) is named,
#    not imported, until you say which environment its values are for.
kagebunshin onboard --file ~/code/widget/production.env --env prod

# 3. Use it. After a reboot or the idle timeout, `kagebunshin unlock`.
aws sso login --profile widget-dev
kagebunshin status                 # where each key comes from, never values; provider health
kagebunshin diff                   # keys in .env.example that no source sets, and how to set them
kagebunshin run -- npm test

# Settings that are not secret go in the project file, unmasked:
kagebunshin project set-var widget dev PORT 3000
```

To teach a coding agent the commands, and for the hooks, see
[agents.md](agents.md#teach-the-agent).
