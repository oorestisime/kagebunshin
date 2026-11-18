use std::collections::HashMap;
use std::time::Duration;

use super::schema::{IdleTimeout, SourcePattern};
use super::*;
use crate::test_support::{Canary, assert_no_canary};
use crate::types::Provider;

const FULL: &str = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git", "https://gitlab.example.com/mirror/widget"]
profile = "acme-dev"
env_example = "apps/web/.env.example"

[envs.dev]

[envs.prod]
profile = "acme-prod"

[[envs.prod.sources]]
provider = "aws_sm"
prefix = "widget/prod/"

[[envs.prod.sources]]
provider = "aws_sm"
secrets = ["widget/prod/a", "widget/prod/b"]
optional = true

[[envs.prod.sources]]
provider = "aws_sm"
secret = "widget/prod/stripe"
key = "STRIPE_SECRET_KEY"
profile = "acme-billing"
region = "us-west-2"
"#;

const MINIMAL: &str = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]
[envs.dev]
"#;

fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
    let map: HashMap<String, OsString> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), OsString::from(v)))
        .collect();
    move |k| map.get(k).cloned()
}

fn project(name: &str, text: &str) -> Result<Project, ConfigError> {
    parse_project(Path::new(&format!("/cfg/projects/{name}.toml")), text)
}

fn project_err(text: &str) -> String {
    project("widget", text).unwrap_err().to_string()
}

fn name(s: &str) -> ProjectName {
    s.parse().unwrap()
}

fn env(s: &str) -> EnvName {
    s.parse().unwrap()
}

#[test]
fn config_dir_resolution() {
    type Vars<'a> = &'a [(&'a str, &'a str)];
    let cases: &[(Vars, Option<&str>)] = &[
        (
            &[
                (CONFIG_DIR_ENV, "/o"),
                ("XDG_CONFIG_HOME", "/x"),
                ("HOME", "/h"),
            ],
            Some("/o"),
        ),
        (
            &[("XDG_CONFIG_HOME", "/x"), ("HOME", "/h")],
            Some("/x/kagebunshin"),
        ),
        (
            &[
                (CONFIG_DIR_ENV, ""),
                ("XDG_CONFIG_HOME", ""),
                ("HOME", "/h"),
            ],
            Some("/h/.config/kagebunshin"),
        ),
        // A relative XDG_CONFIG_HOME is ignored.
        (
            &[("XDG_CONFIG_HOME", "x"), ("HOME", "/h")],
            Some("/h/.config/kagebunshin"),
        ),
        (&[], None),
        (&[(CONFIG_DIR_ENV, "rel")], None),
        (&[("HOME", "rel")], None),
    ];
    for (vars, want) in cases {
        let got = ConfigDir::resolve(env_of(vars));
        match want {
            Some(w) => assert_eq!(got.unwrap().path(), Path::new(w), "{vars:?}"),
            None => assert!(got.is_err(), "{vars:?}"),
        }
    }
    let d = ConfigDir::new("/c");
    assert_eq!(d.config_file(), Path::new("/c/config.toml"));
    assert_eq!(
        d.project_file(&name("widget")),
        Path::new("/c/projects/widget.toml")
    );
}

#[test]
fn full_project_parses() {
    let p = project("widget", FULL).unwrap();
    assert_eq!(p.name, name("widget"));
    let f = &p.file;
    assert_eq!(
        f.remotes.iter().map(RemoteId::as_str).collect::<Vec<_>>(),
        ["github.com/acme/widget", "gitlab.example.com/mirror/widget"]
    );
    assert_eq!(f.profile.as_ref().unwrap().as_str(), "acme-dev");
    assert_eq!(
        f.env_example.as_deref(),
        Some(Path::new("apps/web/.env.example"))
    );
    let prod = &f.envs[&env("prod")];
    assert_eq!(
        prod.sources,
        [
            SourceEntry {
                provider: Provider::AwsSm,
                select: Some(Select::Prefix("widget/prod/".into())),
                optional: false,
                aws: AwsSettings {
                    profile: None,
                    region: None
                },
                sensitive: Vec::new(),
            },
            SourceEntry {
                provider: Provider::AwsSm,
                select: Some(Select::Secrets(vec![
                    "widget/prod/a".into(),
                    "widget/prod/b".into(),
                ])),
                optional: true,
                aws: AwsSettings {
                    profile: None,
                    region: None
                },
                sensitive: Vec::new(),
            },
            SourceEntry {
                provider: Provider::AwsSm,
                select: Some(Select::Secret {
                    name: "widget/prod/stripe".into(),
                    key: Some("STRIPE_SECRET_KEY".parse().unwrap()),
                }),
                optional: false,
                aws: AwsSettings {
                    profile: Some("acme-billing".to_owned().try_into().unwrap()),
                    region: Some("us-west-2".to_owned().try_into().unwrap())
                },
                sensitive: Vec::new(),
            },
        ]
    );
    assert_eq!(f.envs[&env("dev")], EnvFile::default());
}

#[test]
fn project_file_round_trips() {
    for text in [FULL, MINIMAL] {
        let a = project("widget", text).unwrap();
        let written = a.file.to_toml();
        let b = project("widget", &written).unwrap();
        assert_eq!(a.file, b.file, "{written}");
        // Writing is stable: a second round trip produces the same text.
        assert_eq!(b.file.to_toml(), written);
    }
    // Remotes are written in canonical form.
    let written = project("widget", MINIMAL).unwrap().file.to_toml();
    assert!(
        written.contains(r#"remotes = ["github.com/acme/widget"]"#),
        "{written}"
    );
}

#[test]
fn typos_are_errors_with_a_line_number() {
    let cases: &[(&str, &str, usize)] = &[
        (
            "schema = 1\nremotes = [\"github.com/a/b\"]\nsensitve_envs = [\"prod\"]\n[envs.dev]\n",
            "unknown field `sensitve_envs`",
            3,
        ),
        (
            "schema = 1\nremotes = [\"github.com/a/b\"]\n[envs.dev]\nsensitve_keys = [\"A\"]\n",
            "unknown field `sensitve_keys`",
            4,
        ),
        (
            "schema = 1\nremotes = [\"github.com/a/b\"]\n[envs.dev]\n[[envs.dev.sources]]\nprovider = \"aws_sm\"\nprefx = \"a/\"\n",
            "unknown field `prefx`",
            6,
        ),
        (
            "schema = 1\nremote = [\"github.com/a/b\"]\n[envs.dev]\n",
            "unknown field `remote`",
            2,
        ),
    ];
    for (text, want, line) in cases {
        match project("widget", text) {
            Err(ConfigError::Parse {
                at: Some((l, _)),
                message,
                ..
            }) => {
                assert!(message.contains(want), "{message}");
                assert_eq!(l, *line, "{message}");
            }
            other => panic!("{want}: {other:?}"),
        }
    }
    let err =
        project_err("schema = 1\nremotes = [\"github.com/a/b\"]\nsensitve_envs = []\n[envs.dev]\n");
    assert!(
        err.starts_with("/cfg/projects/widget.toml:3:1: unknown field `sensitve_envs`"),
        "{err}"
    );

    let err = parse_config(
        Path::new("/cfg/config.toml"),
        "schema = 1\n[masking]\nmin_length = 8\n",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains(":3:1: unknown field `min_length`"), "{err}");
}

#[test]
fn schema_is_required_and_must_be_1() {
    let missing = project_err("remotes = [\"github.com/a/b\"]\n[envs.dev]\n");
    assert!(missing.contains("missing field `schema`"), "{missing}");
    let two = project_err("schema = 2\nremotes = [\"github.com/a/b\"]\n[envs.dev]\n");
    assert!(two.contains(":1:10: schema 2 is not supported"), "{two}");
    assert!(parse_config(Path::new("c.toml"), "default_env = \"dev\"\n").is_err());
}

#[test]
fn sources_set_exactly_one_selector() {
    let source = |body: &str| {
        project_err(&format!(
            "schema = 1\nremotes = [\"github.com/a/b\"]\n[envs.dev]\n[[envs.dev.sources]]\nprovider = \"aws_sm\"\n{body}\n"
        ))
    };
    let one_of = "a source must set exactly one of secret, secrets or prefix";
    for body in [
        "",
        "secret = \"a\"\nprefix = \"a/\"",
        "secrets = [\"a\"]\nprefix = \"a/\"",
        "secret = \"a\"\nsecrets = [\"b\"]",
        "optional = true",
    ] {
        assert!(source(body).contains(one_of), "{body}: {}", source(body));
    }
    let cases = [
        (
            "prefix = \"a/\"\nkey = \"A\"",
            "key can only be used with secret",
        ),
        (
            "secrets = [\"a\"]\nkey = \"A\"",
            "key can only be used with secret",
        ),
        ("secrets = []", "secrets must list at least one secret"),
        ("secrets = [\"a\", \"a\"]", "secret a is listed twice"),
        ("prefix = \"\"", "prefix must not be empty"),
        ("secret = \"a b\"", "secret must not contain whitespace"),
        (
            "secret = \"a\"\nkey = \"not-a-key\"",
            "key name contains a character",
        ),
        (
            "secret = \"a\"\nprovider2 = \"x\"",
            "unknown field `provider2`",
        ),
    ];
    for (body, want) in cases {
        let err = source(body);
        assert!(err.contains(want), "{body}: {err}");
        // Errors from inside a source point at it.
        assert!(err.contains("widget.toml:"), "{err}");
    }
    // Only a file source may leave out all three, and then not with `key`.
    let file = |body: &str| {
        project(
            "widget",
            &format!(
                "schema = 1\nremotes = [\"github.com/a/b\"]\n[[envs.dev.sources]]\nprovider = \"file\"\n{body}\n"
            ),
        )
    };
    let err = file("key = \"A\"").unwrap_err().to_string();
    assert!(err.contains("key can only be used with secret"), "{err}");
    let err = file("secret = \"a\"\nprefix = \"a/\"")
        .unwrap_err()
        .to_string();
    assert!(err.contains(one_of), "{err}");
    let proton = project_err(
        "schema = 1\nremotes = [\"github.com/a/b\"]\n[[envs.dev.sources]]\nprovider = \"proton\"\n",
    );
    assert!(proton.contains(one_of), "{proton}");
    let proton = |select: &str| {
        project(
            "widget",
            &format!(
                "schema = 1\nremotes = [\"github.com/a/b\"]\n[[envs.dev.sources]]\nprovider = \"proton\"\n{select}\n"
            ),
        )
    };
    let err = proton("prefix = \"global/\"").unwrap_err().to_string();
    assert!(
        err.contains("keys in the global vault are added one at a time"),
        "{err}"
    );
    proton("secret = \"global/OPENAI_KEY\"").unwrap();
    proton("prefix = \"widget/\"").unwrap();
    for body in ["", "optional = true"] {
        let p = file(body).unwrap();
        let s = &p.file.envs[&env("dev")].sources[0];
        assert_eq!(s.select, None, "{body}");
        assert_eq!(s.optional, body.contains("optional"));
    }

    let unknown = project_err(
        "schema = 1\nremotes = [\"github.com/a/b\"]\n[envs.dev]\n[[envs.dev.sources]]\nprovider = \"vault\"\nprefix = \"a/\"\n",
    );
    // The value itself is not repeated; see type_errors_name_the_field_not_the_value.
    assert!(
        unknown.ends_with(
            ":5:12: unknown variant, expected one of `aws_sm`, `file`, `proton` (field provider)"
        ),
        "{unknown}"
    );
}

#[test]
fn cross_field_checks() {
    let cases = [
        (
            "schema = 1\nremotes = []\n[envs.dev]\n",
            "remotes must list at least one git remote",
        ),
        (
            "schema = 1\nremotes = [\"git@github.com:a/b.git\", \"https://GitHub.com/a/b\"]\n[envs.dev]\n",
            "remote github.com/a/b is listed twice",
        ),
        (
            "schema = 1\nremotes = [\"github.com/a/b\"]\nenvs = {}\n",
            "at least one [envs.<name>] table is required",
        ),
        (
            "schema = 1\nremotes = [\"github.com/a/b\"]\nsensitive_envs = [\"prod\"]\n[envs.prod]\n",
            "unknown field `sensitive_envs`",
        ),
        (
            "schema = 1\nremotes = [\"/srv/git/widget\"]\n[envs.dev]\n",
            "remote is a local path",
        ),
        (
            "schema = 1\nremotes = [\"github.com/a/b\"]\n[envs.Dev]\n",
            "environment name contains a character",
        ),
        (
            "schema = 1\nremotes = [\"github.com/a/b\"]\nprofile = \"\"\n[envs.dev]\n",
            "profile must be 1 to 128 bytes",
        ),
    ];
    for (text, want) in cases {
        let err = project_err(text);
        assert!(err.contains(want), "{want}: {err}");
    }
}

#[test]
fn file_name_must_be_a_project_name() {
    for bad in ["Widget", "my.widget", "-w"] {
        assert!(
            matches!(project(bad, MINIMAL), Err(ConfigError::BadFileName { .. })),
            "{bad}"
        );
    }
}

#[test]
fn parse_errors_do_not_quote_the_file() {
    let canary = Canary::new();
    let texts = [
        // A syntax error on a line holding a value-like string.
        format!("schema = 1\nprofile = \"{}\" oops\n", canary.value()),
        // A token in a remote that is otherwise invalid.
        format!(
            "schema = 1\nremotes = [\"https://x:{}@github.com\"]\n[envs.dev]\n",
            canary.value()
        ),
        format!(
            "schema = 1\nremotes = [\"github.com/a/b\"]\n[envs.dev]\nsensitive_keys = [\"{}-x\"]\n",
            canary.value()
        ),
    ];
    for text in texts {
        let err = project("widget", &text).unwrap_err();
        assert_no_canary(&canary, &err.to_string());
        assert_no_canary(&canary, &format!("{err:?}"));
    }
}

/// `sensitive_keys` was never enforced. A file that sets it does not load,
/// so nothing that reads it (run, session) serves the environment.
#[test]
fn sensitive_keys_is_refused_with_a_pointer_to_the_marks() {
    let text = "schema = 1\nremotes = [\"github.com/a/b\"]\n[envs.dev]\nsensitive_keys = [\"STRIPE_KEY\"]\n";
    let err = project("widget", text).unwrap_err().to_string();
    assert!(err.contains("sensitive_keys is not supported"), "{err}");
    assert!(err.contains("in the app"), "{err}");
    assert!(!err.contains("STRIPE_KEY"), "{err}");
    // Even empty.
    let text = "schema = 1\nremotes = [\"github.com/a/b\"]\n[envs.dev]\nsensitive_keys = []\n";
    assert!(project("widget", text).is_err());
}

/// A `sensitive` flag in a project file loads, to be copied into the store
/// at unlock: on an environment, or as secrets an `aws_sm` source lists.
/// Listing secrets on another provider is refused, without the value.
#[test]
fn sensitive_flags_in_a_project_file_load() {
    let canary = Canary::new();
    let head = "schema = 1\nremotes = [\"github.com/a/b\"]\n";
    let f = project(
        "widget",
        &format!(
            "{head}[envs.prod]\nsensitive = true\n[[envs.prod.sources]]\nprovider = \"aws_sm\"\n\
             prefix = \"a/\"\nsensitive = [\"a/db\"]\n"
        ),
    )
    .unwrap()
    .file;
    let prod = &f.envs[&env("prod")];
    assert!(prod.sensitive);
    assert_eq!(prod.sources[0].sensitive, ["a/db"]);
    let f = project("widget", &format!("{head}[envs.prod]\nsensitive = false\n"))
        .unwrap()
        .file;
    assert!(!f.envs[&env("prod")].sensitive);
    let text = format!(
        "{head}[[envs.prod.sources]]\nprovider = \"file\"\nsensitive = [\"{}\"]\n",
        canary.value()
    );
    let err = project("widget", &text).unwrap_err().to_string();
    assert!(
        err.contains("sensitive can only be used with provider"),
        "{err}"
    );
    assert_no_canary(&canary, &err);
}

#[test]
fn type_errors_name_the_field_not_the_value() {
    let c = Canary::new();
    let v = c.value();
    let head = "schema = 1\nremotes = [\"github.com/a/b\"]\n[envs.dev]\n[[envs.dev.sources]]\n";
    let cases = [
        // A string where a list belongs: serde would quote it.
        (
            format!("schema = 1\nremotes = \"https://x:{v}@github.com/a/b\"\n"),
            "/cfg/projects/widget.toml:2:11: invalid type: string, expected a sequence (field remotes)",
        ),
        (
            format!("{head}provider = \"aws_sm\"\nsecret = \"a\"\noptional = \"{v}\"\n"),
            "/cfg/projects/widget.toml:7:12: invalid type: string, expected a boolean (field optional)",
        ),
        (
            format!("{head}provider = \"{v}\"\nsecret = \"a\"\n"),
            "/cfg/projects/widget.toml:5:12: unknown variant, expected one of",
        ),
        // In a multi-line array the line holds no key, so none is named.
        (
            format!("schema = 1\nremotes = [\n  \"github.com/a/b\",\n  {{ x = \"{v}\" }},\n]\n"),
            "/cfg/projects/widget.toml:4:3: invalid type: map, expected a string\n",
        ),
    ];
    for (text, want) in cases {
        let err = project("widget", &text).unwrap_err();
        let msg = err.to_string();
        assert_no_canary(&c, &msg);
        assert_no_canary(&c, &format!("{err:?}"));
        match want.strip_suffix('\n') {
            Some(exact) => assert_eq!(msg, exact),
            None => assert!(msg.starts_with(want), "{msg}"),
        }
    }
    let err = parse_config(
        Path::new("/cfg/config.toml"),
        &format!("schema = 1\nidle_timeout = {{ token = \"{v}\" }}\n"),
    )
    .unwrap_err();
    assert_no_canary(&c, &err.to_string());
    assert!(err.to_string().contains("(field idle_timeout)"), "{err}");
}

#[test]
fn config_defaults_and_full() {
    let d = Config::default();
    assert_eq!(d.default_env, env("dev"));
    assert_eq!(d.idle_timeout.get(), Duration::from_mins(30));
    assert_eq!(d.approval_timeout.get(), Duration::from_mins(5));
    assert_eq!(d.default_provider, Provider::File);
    assert!(d.sensitive_source_patterns.is_empty());
    assert_eq!(d.masking.min_len.get(), 8);
    assert_eq!(parse_config(Path::new("c"), "schema = 1\n").unwrap(), d);

    let c = parse_config(
        Path::new("c"),
        r#"
schema = 1
default_env = "local"
idle_timeout = "2h"
approval_timeout = "90s"
default_provider = "aws_sm"
sensitive_source_patterns = ["*prod*", "*live*"]
[masking]
min_len = 12
"#,
    )
    .unwrap();
    assert_eq!(c.default_env, env("local"));
    assert_eq!(c.idle_timeout.get(), Duration::from_secs(7200));
    assert_eq!(c.approval_timeout.get(), Duration::from_secs(90));
    assert_eq!(c.default_provider, Provider::AwsSm);
    assert_eq!(c.sensitive_source_patterns.len(), 2);
    assert_eq!(c.masking.min_len.get(), 12);

    let round = toml::to_string(&c).unwrap();
    assert_eq!(parse_config(Path::new("c"), &round).unwrap(), c);

    for (body, want) in [
        ("min_len = 0", "between 1 and 1024"),
        ("idle_timeout = \"0m\"", "more than zero"),
        ("approval_timeout = \"0s\"", "more than zero"),
        ("approval_timeout = \"31m\"", "at most 30m"),
        (
            "approval_timeout = \"soon\"",
            "a whole number followed by s or m",
        ),
        ("sensitive_source_patterns = [\"**\"]", "other than `*`"),
    ] {
        let (table, line) = if body.starts_with("min_len") {
            ("[masking]\n", body)
        } else {
            ("", body)
        };
        let text = format!("schema = 1\n{table}{line}\n");
        let err = parse_config(Path::new("c"), &text).unwrap_err().to_string();
        assert!(err.contains(want), "{body}: {err}");
    }
}

#[test]
fn idle_timeout_format() {
    let ok = [
        ("90s", 90),
        ("30m", 1800),
        ("8h", 28_800),
        ("1d", 86_400),
        ("30d", 2_592_000),
    ];
    for (s, secs) in ok {
        let t = IdleTimeout::try_from(s.to_owned()).unwrap();
        assert_eq!(t.get(), Duration::from_secs(secs), "{s}");
        assert_eq!(String::from(t), s);
    }
    assert_eq!(
        String::from(IdleTimeout::try_from("120m".to_owned()).unwrap()),
        "2h"
    );
    for s in [
        "",
        "30",
        "m",
        "1.5h",
        "-1h",
        "1 h",
        "1H",
        "31d",
        "99999999999999999999d",
    ] {
        assert!(IdleTimeout::try_from(s.to_owned()).is_err(), "{s:?}");
    }
}

#[test]
fn env_settings_apply_conventions() {
    let config = Config::default();
    let reg = Registry::new(config, vec![project("widget", FULL).unwrap()]).unwrap();
    let p = reg.project(&name("widget")).unwrap();

    // dev declares no sources, so it gets the local file's [widget.dev]
    // section from the default provider.
    let dev = reg.env(p, None).unwrap();
    assert_eq!(dev.env, env("dev"));
    assert_eq!(
        dev.sources,
        [SourceSpec {
            provider: Provider::File,
            select: Select::Secret {
                name: "widget.dev".into(),
                key: None,
            },
            optional: false,
            aws: AwsSettings {
                profile: None,
                region: None
            },
            missing_is_empty: true,
        }]
    );

    let prod = reg.env(p, Some(&env("prod"))).unwrap();
    assert_eq!(prod.sources.len(), 3);

    let err = reg.env(p, Some(&env("staging"))).unwrap_err().to_string();
    assert_eq!(
        err,
        "project widget has no environment staging; add it with \
         `kagebunshin project add-env widget staging`"
    );

    // The default env and provider come from config.toml, and the default
    // source's shape follows the provider.
    let local = || {
        project(
            "widget",
            "schema = 1\nremotes = [\"github.com/a/b\"]\n[envs.local]\n",
        )
        .unwrap()
    };
    let with = |provider: &str| {
        let config = parse_config(
            Path::new("c"),
            &format!("schema = 1\ndefault_env = \"local\"\ndefault_provider = \"{provider}\"\n"),
        )
        .unwrap();
        Registry::new(config, vec![local()]).unwrap()
    };

    let reg = with("file");
    let s = reg
        .env(reg.project(&name("widget")).unwrap(), None)
        .unwrap();
    assert_eq!(s.env, env("local"));
    assert_eq!(
        s.sources,
        [SourceSpec {
            provider: Provider::File,
            select: Select::Secret {
                name: "widget.local".into(),
                key: None,
            },
            optional: false,
            aws: AwsSettings {
                profile: None,
                region: None
            },
            missing_is_empty: true,
        }]
    );

    let reg = with("aws_sm");
    let s = reg
        .env(reg.project(&name("widget")).unwrap(), None)
        .unwrap();
    assert_eq!(
        s.sources,
        [SourceSpec {
            provider: Provider::AwsSm,
            select: Select::Prefix("widget/local/".into()),
            optional: false,
            aws: AwsSettings {
                profile: None,
                region: None
            },
            missing_is_empty: false,
        }]
    );

    let reg = with("proton");
    let err = reg
        .env(reg.project(&name("widget")).unwrap(), None)
        .unwrap_err();
    assert!(
        matches!(err, ConfigError::NoDefaultSource { .. }),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "environment local of project widget lists no sources, and the proton provider has no \
         default source; add one with `kagebunshin project add-source widget local --provider \
         PROVIDER --prefix PREFIX`"
    );

    // Declared sources are used as they are, whatever the default provider.
    let reg = with("proton");
    let declared = project(
        "gadget",
        "schema = 1\nremotes = [\"github.com/a/c\"]\n[envs.local]\n[[envs.local.sources]]\nprovider = \"proton\"\nsecret = \"gadget\"\n",
    )
    .unwrap();
    let reg = Registry::new(reg.config.clone(), vec![declared]).unwrap();
    let s = reg
        .env(reg.project(&name("gadget")).unwrap(), None)
        .unwrap();
    assert_eq!(s.sources[0].provider, Provider::Proton);
}

/// The spec's sample: a bare `provider = "file"` source reads the env's own
/// `[<project>.<env>]` section, whatever `default_provider` is, and can sit
/// next to sources that name their selector.
#[test]
fn bare_file_source_reads_the_env_section() {
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/blog.git"]

[[envs.dev.sources]]
provider = "file"

[[envs.staging.sources]]
provider = "aws_sm"
prefix = "blog/staging/"

[[envs.staging.sources]]
provider = "file"
optional = true
"#;
    let section = |name: &str| Select::Secret {
        name: name.into(),
        key: None,
    };
    for provider in ["file", "aws_sm", "proton"] {
        let config = parse_config(
            Path::new("c"),
            &format!("schema = 1\ndefault_provider = \"{provider}\"\n"),
        )
        .unwrap();
        let reg = Registry::new(config, vec![project("blog", text).unwrap()]).unwrap();
        let p = reg.project(&name("blog")).unwrap();
        assert_eq!(
            reg.env(p, None).unwrap().sources,
            [SourceSpec {
                provider: Provider::File,
                select: section("blog.dev"),
                optional: false,
                aws: AwsSettings {
                    profile: None,
                    region: None
                },
                missing_is_empty: true,
            }],
            "{provider}"
        );
        assert_eq!(
            reg.env(p, Some(&env("staging"))).unwrap().sources,
            [
                SourceSpec {
                    provider: Provider::AwsSm,
                    select: Select::Prefix("blog/staging/".into()),
                    optional: false,
                    aws: AwsSettings {
                        profile: None,
                        region: None
                    },
                    missing_is_empty: false,
                },
                SourceSpec {
                    provider: Provider::File,
                    select: section("blog.staging"),
                    optional: true,
                    aws: AwsSettings {
                        profile: None,
                        region: None
                    },
                    missing_is_empty: true,
                },
            ],
            "{provider}"
        );
    }

    // It stays bare when written back.
    let p = project("blog", text).unwrap();
    let written = p.file.to_toml();
    assert!(!written.contains("secret"), "{written}");
    assert_eq!(project("blog", &written).unwrap().file, p.file);
}

#[test]
fn two_projects_cannot_claim_one_remote() {
    let a = project(
        "alpha",
        "schema = 1\nremotes = [\"git@github.com:acme/widget.git\"]\n[envs.dev]\n",
    )
    .unwrap();
    let b = project(
        "beta",
        "schema = 1\nremotes = [\"github.com/acme/other\", \"https://github.com/acme/widget\"]\n[envs.dev]\n",
    )
    .unwrap();
    let err = Registry::new(Config::default(), vec![a, b])
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "remote github.com/acme/widget is claimed by both project alpha and project beta"
    );
}

#[test]
fn load_reads_the_directory() {
    let d = tempfile::tempdir().unwrap();
    let dir = ConfigDir::new(d.path().join("kb"));

    // Nothing there yet: defaults and no projects.
    let reg = Registry::load(&dir).unwrap();
    assert_eq!(reg.config, Config::default());
    assert_eq!(reg.projects().count(), 0);

    fs::create_dir_all(dir.projects_dir()).unwrap();
    fs::write(dir.config_file(), "schema = 1\nidle_timeout = \"5m\"\n").unwrap();
    fs::write(dir.project_file(&name("widget")), FULL).unwrap();
    fs::write(
        dir.project_file(&name("gadget")),
        "schema = 1\nremotes = [\"github.com/acme/gadget\"]\n[envs.dev]\n",
    )
    .unwrap();
    // Skipped: temp files, hidden files, other extensions.
    fs::write(dir.projects_dir().join(".widget.toml.0123.tmp"), "garbage").unwrap();
    fs::write(dir.projects_dir().join(".hidden.toml"), "garbage").unwrap();
    fs::write(dir.projects_dir().join("notes.txt"), "garbage").unwrap();
    fs::write(dir.projects_dir().join("widget.toml~"), "garbage").unwrap();

    let reg = Registry::load(&dir).unwrap();
    assert_eq!(reg.config.idle_timeout.get(), Duration::from_secs(300));
    let names: Vec<_> = reg.projects().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["gadget", "widget"]);
    assert_eq!(
        reg.project(&name("widget")).unwrap().path,
        dir.project_file(&name("widget"))
    );

    // One bad file fails the whole load, naming the file.
    fs::write(
        dir.projects_dir().join("broken.toml"),
        "schema = 1\nremotes = [\"github.com/x/y\"]\n[envs.dev]\nbogus = 1\n",
    )
    .unwrap();
    let err = Registry::load(&dir).unwrap_err().to_string();
    assert!(
        err.contains("broken.toml:4:1: unknown field `bogus`"),
        "{err}"
    );
}

#[test]
fn round_trip_through_the_atomic_writer() {
    let d = tempfile::tempdir().unwrap();
    let dir = ConfigDir::new(d.path());
    fs::create_dir(dir.projects_dir()).unwrap();
    let p = project("widget", FULL).unwrap();
    let path = dir.project_file(&p.name);
    crate::atomic::write_private(&path, p.file.to_toml().as_bytes()).unwrap();
    let reg = Registry::load(&dir).unwrap();
    assert_eq!(reg.project(&p.name).unwrap().file, p.file);
}

/// A temp dir for git repos, with git cut off from the user's config.
struct GitSandbox {
    dir: tempfile::TempDir,
}

impl GitSandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("home")).unwrap();
        Self { dir }
    }

    /// Canonical, since git prints canonical paths (on macOS /var is a
    /// symlink to /private/var).
    fn path(&self) -> PathBuf {
        self.dir.path().canonicalize().unwrap()
    }

    fn git(&self) -> Git {
        Git::default()
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", self.path().join("home"))
            .env("GIT_CEILING_DIRECTORIES", self.path())
    }

    /// Runs git for test setup with the same isolation.
    fn run(&self, dir: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", self.path().join("home"))
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A new repo at `<sandbox>/<name>` with the given remotes.
    fn repo(&self, name: &str, remotes: &[(&str, &str)]) -> PathBuf {
        let root = self.path().join(name);
        fs::create_dir(&root).unwrap();
        self.run(&root, &["init", "-q", "-b", "main"]);
        for (remote, url) in remotes {
            self.run(&root, &["remote", "add", "--", remote, url]);
        }
        root
    }
}

fn registry(projects: &[(&str, &[&str])]) -> Registry {
    let projects = projects
        .iter()
        .map(|(n, remotes)| {
            let list: Vec<String> = remotes.iter().map(|r| format!("{r:?}")).collect();
            project(
                n,
                &format!("schema = 1\nremotes = [{}]\n[envs.dev]\n", list.join(", ")),
            )
            .unwrap()
        })
        .collect();
    Registry::new(Config::default(), projects).unwrap()
}

fn ids(urls: &[&str]) -> Vec<RemoteId> {
    urls.iter()
        .map(|u| RemoteId::from_url(u).unwrap())
        .collect()
}

#[test]
fn checkout_root_and_remotes() {
    let s = GitSandbox::new();
    let root = s.repo(
        "widget",
        &[
            ("origin", "git@github.com:me/widget.git"),
            ("upstream", "https://github.com/acme/widget"),
            ("local", "/srv/git/widget.git"),
            ("dup", "ssh://git@github.com/me/widget"),
        ],
    );
    // A second push/fetch URL on one remote.
    s.run(
        &root,
        &[
            "remote",
            "set-url",
            "--add",
            "origin",
            "https://gitlab.example.com/me/widget",
        ],
    );
    let sub = root.join("apps/web");
    fs::create_dir_all(&sub).unwrap();

    let c = s.git().checkout(&sub).unwrap();
    assert_eq!(c.root, root);
    assert_eq!(
        c.remotes,
        ids(&[
            "https://github.com/me/widget",
            "https://gitlab.example.com/me/widget",
            "https://github.com/acme/widget",
        ])
    );
}

#[test]
fn outside_a_checkout() {
    let s = GitSandbox::new();
    let plain = s.path().join("plain");
    fs::create_dir(&plain).unwrap();
    let err = s.git().checkout(&plain).unwrap_err();
    assert!(matches!(err, GitError::NotARepo { .. }), "{err:?}");
    assert!(err.to_string().ends_with("is not inside a git checkout"));

    // Command looks the program up in the child's PATH.
    let err = Git::default()
        .env("PATH", "/nonexistent")
        .checkout(&plain)
        .unwrap_err();
    assert!(matches!(err, GitError::Spawn(_)), "{err:?}");
}

#[test]
fn worktrees_resolve_to_the_same_project() {
    let s = GitSandbox::new();
    let main = s.repo("widget", &[("origin", "git@github.com:acme/widget.git")]);
    s.run(
        &main,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ],
    );
    let wt = s.path().join("widget-feature");
    s.run(
        &main,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "feature",
            wt.to_str().unwrap(),
        ],
    );

    let reg = registry(&[
        ("widget", &["github.com/acme/widget"]),
        ("other", &["github.com/acme/other"]),
    ]);
    let (a, ca) = reg.resolve(&s.git(), &main).unwrap();
    let (b, cb) = reg.resolve(&s.git(), &wt).unwrap();
    assert_eq!(a.name, name("widget"));
    assert_eq!(b.name, name("widget"));
    assert_eq!(ca.root, main);
    assert_eq!(cb.root, wt);
    assert_eq!(ca.remotes, cb.remotes);
}

#[test]
fn any_remote_may_match() {
    let s = GitSandbox::new();
    let fork = s.repo(
        "fork",
        &[
            ("origin", "git@github.com:me/widget.git"),
            ("upstream", "git@github.com:acme/widget.git"),
        ],
    );
    let reg = registry(&[("widget", &["https://github.com/acme/widget"])]);
    let (p, _) = reg.resolve(&s.git(), &fork).unwrap();
    assert_eq!(p.name, name("widget"));

    // Two remotes claimed by the same project are fine.
    let reg = registry(&[(
        "widget",
        &["github.com/acme/widget", "github.com/me/widget"],
    )]);
    assert_eq!(reg.resolve(&s.git(), &fork).unwrap().0.name, name("widget"));
}

#[test]
fn unknown_project_errors_carry_no_credentials() {
    let c = Canary::new();
    let v = c.value();
    let reg = registry(&[("widget", &["github.com/acme/widget"])]);
    let remotes = ids(&[
        &format!("https://x-access-token:{v}@github.com/acme/other.git?t={v}#{v}"),
        &format!("git@github.com:acme/other.git#{v}"),
    ]);
    let err = reg.find(Place::remotes(&remotes)).unwrap_err().to_string();
    assert_no_canary(&c, &err);
    assert!(err.contains("github.com/acme/other"), "{err}");
    // A query or fragment does not stop the remote matching.
    let remotes = ids(&[&format!("https://github.com/acme/widget?t={v}")]);
    assert_eq!(
        reg.find(Place::remotes(&remotes)).unwrap().project.name,
        name("widget")
    );
}

#[test]
fn matching_two_projects_is_an_error() {
    let s = GitSandbox::new();
    let fork = s.repo(
        "fork",
        &[
            ("origin", "git@github.com:me/widget.git"),
            ("upstream", "git@github.com:acme/widget.git"),
        ],
    );
    let reg = registry(&[
        ("mine", &["github.com/me/widget"]),
        ("widget", &["github.com/acme/widget"]),
    ]);
    let err = reg.resolve(&s.git(), &fork).unwrap_err();
    assert!(matches!(err, MatchError::Ambiguous { .. }), "{err:?}");
    assert_eq!(
        err.to_string(),
        "this checkout matches more than one project (github.com/me/widget is mine, \
         github.com/acme/widget is widget); a checkout must match exactly one"
    );
}

#[test]
fn no_match_says_run_init() {
    let s = GitSandbox::new();
    let token = Canary::new();
    let url = format!(
        "https://x-access-token:{}@github.com/acme/new.git",
        token.value()
    );
    let repo = s.repo("new", &[("origin", &url)]);
    let reg = registry(&[("widget", &["github.com/acme/widget"])]);
    let err = reg.resolve(&s.git(), &repo).unwrap_err();
    let msg = err.to_string();
    assert_eq!(
        msg,
        "unknown project: no project claims github.com/acme/new; run kagebunshin project init"
    );
    assert_no_canary(&token, &msg);
    assert_no_canary(&token, &format!("{err:?}"));

    let local_only = s.repo("local", &[("origin", "/srv/git/local.git")]);
    let err = reg.resolve(&s.git(), &local_only).unwrap_err();
    assert!(matches!(err, MatchError::NoRemotes { .. }), "{err:?}");

    let none = s.repo("none", &[]);
    assert!(matches!(
        reg.resolve(&s.git(), &none),
        Err(MatchError::NoRemotes { .. })
    ));
}

#[test]
fn find_without_git() {
    let reg = registry(&[
        ("alpha", &["github.com/acme/alpha"]),
        ("beta", &["github.com/acme/beta"]),
    ]);
    let alpha = ids(&["https://github.com/acme/alpha"]);
    assert_eq!(
        reg.find(Place::remotes(&alpha)).unwrap().project.name,
        name("alpha")
    );
    assert!(matches!(
        reg.find(Place::remotes(&ids(&["https://github.com/acme/gamma"]))),
        Err(MatchError::Unknown { .. })
    ));
    assert!(matches!(
        reg.find(Place::remotes(&ids(&[
            "https://github.com/acme/alpha",
            "https://github.com/acme/beta"
        ]))),
        Err(MatchError::Ambiguous { .. })
    ));
}

/// A project claiming `remote`, with `path` if given.
fn scoped(n: &str, remote: &str, path: Option<&str>) -> Project {
    let path = path.map(|p| format!("path = {p:?}\n")).unwrap_or_default();
    project(
        n,
        &format!("schema = 1\nremotes = [{remote:?}]\n{path}[envs.dev]\n"),
    )
    .unwrap()
}

fn at<'a>(remotes: &'a [RemoteId], subdir: &'a str) -> Place<'a> {
    Place {
        subdir: Some(Path::new(subdir)),
        ..Place::remotes(remotes)
    }
}

#[test]
fn project_paths_are_normalised() {
    let ok = |s: &str| ProjectPath::try_from(s.to_owned()).unwrap().to_string();
    assert_eq!(ok("apps/web"), "apps/web");
    assert_eq!(ok("apps/web/"), "apps/web");
    assert_eq!(ok("./apps//web/."), "apps/web");
    for bad in [
        "",
        ".",
        "./",
        "../web",
        "apps/../web",
        "/srv/web",
        "apps/\nweb",
    ] {
        assert!(ProjectPath::try_from(bad.to_owned()).is_err(), "{bad:?}");
    }

    // Written back normalised, and read back the same.
    let p = scoped("web", "github.com/acme/mono", Some("./apps/web/"));
    assert_eq!(p.file.path.as_ref().unwrap().as_str(), "apps/web");
    let written = p.file.to_toml();
    assert!(written.contains("path = \"apps/web\""), "{written}");
    assert_eq!(project("web", &written).unwrap().file, p.file);
    // No path is not written at all.
    let whole = scoped("mono", "github.com/acme/mono", None);
    assert!(!whole.file.to_toml().contains("path"));

    let err = project(
        "web",
        "schema = 1\nremotes = [\"github.com/acme/mono\"]\npath = \"\"\n[envs.dev]\n",
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("leave it out for the whole repository"),
        "{err}"
    );
}

#[test]
fn projects_share_a_remote_with_different_paths() {
    let r = "github.com/acme/mono";
    let reg = Registry::new(
        Config::default(),
        vec![
            scoped("mono", r, None),
            scoped("web", r, Some("apps/web")),
            scoped("api", r, Some("apps/api")),
        ],
    );
    assert!(reg.is_ok());

    let err = Registry::new(
        Config::default(),
        vec![
            scoped("web", r, Some("apps/web")),
            scoped("site", r, Some("apps/web/")),
        ],
    )
    .unwrap_err()
    .to_string();
    assert_eq!(
        err,
        "remote github.com/acme/mono is claimed by both project web and project site with path apps/web"
    );
}

#[test]
fn the_longest_path_wins() {
    let r = "github.com/acme/mono";
    let reg = Registry::new(
        Config::default(),
        vec![
            scoped("apps", r, Some("apps")),
            scoped("back", r, Some("apps/back")),
            scoped("deep", r, Some("apps/back/worker")),
        ],
    )
    .unwrap();
    let remotes = ids(&["https://github.com/acme/mono"]);
    let pick = |sub: &str| {
        reg.find(at(&remotes, sub))
            .unwrap()
            .project
            .name
            .to_string()
    };
    assert_eq!(pick("apps/back"), "back");
    assert_eq!(pick("apps/back/src/lib"), "back");
    assert_eq!(pick("apps/back/worker"), "deep");
    // Whole components only: apps/backend is not inside apps/back.
    assert_eq!(pick("apps/backend"), "apps");
    assert_eq!(pick("apps"), "apps");
    assert!(
        reg.find(at(&remotes, "apps/back"))
            .unwrap()
            .warnings
            .is_empty()
    );

    // Outside every path: an error naming the folders.
    let err = reg.find(at(&remotes, "docs")).unwrap_err();
    assert!(matches!(err, MatchError::NoPathMatches { .. }), "{err:?}");
    assert_eq!(
        err.to_string(),
        "docs is in no project: this repository has one project per folder, apps (apps), \
         back (apps/back), deep (apps/back/worker); run from one of those folders, or pass \
         --project NAME"
    );
    let err = reg.find(Place::remotes(&remotes)).unwrap_err().to_string();
    assert!(
        err.starts_with("the repository root is in no project:"),
        "{err}"
    );
}

#[test]
fn a_whole_repository_project_answers_elsewhere_with_a_warning() {
    let r = "github.com/acme/mono";
    let reg = Registry::new(
        Config::default(),
        vec![scoped("mono", r, None), scoped("web", r, Some("apps/web"))],
    )
    .unwrap();
    let remotes = ids(&["https://github.com/acme/mono"]);
    let found = reg.find(at(&remotes, "apps/web/src")).unwrap();
    assert_eq!(found.project.name, name("web"));
    assert!(found.warnings.is_empty());

    let found = reg.find(at(&remotes, "apps/wbe")).unwrap();
    assert_eq!(found.project.name, name("mono"));
    assert_eq!(
        found.warnings,
        [
            "project mono has no path, so it answers here, while web (apps/web) claims this \
          repository too; if one of them should answer here, check its path"
        ]
    );
}

/// A project's path is matched as it resolves on disk, as the working
/// directory is: through a symlink, it still answers. Two projects whose
/// paths resolve to one folder are an error.
#[cfg(unix)]
#[test]
fn paths_are_matched_as_they_resolve_on_disk() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("packages/web/src")).unwrap();
    std::fs::create_dir(tmp.path().join("apps")).unwrap();
    std::os::unix::fs::symlink("../packages/web", tmp.path().join("apps/web")).unwrap();
    let r = "github.com/acme/mono";
    let remotes = ids(&["https://github.com/acme/mono"]);
    let checkout = Checkout {
        root: tmp.path().to_owned(),
        remotes: remotes.clone(),
    };
    let subdir = checkout.subdir(&tmp.path().join("apps/web/src")).unwrap();
    assert_eq!(subdir, Path::new("packages/web/src"), "the cwd, resolved");
    let place = Place {
        subdir: Some(&subdir),
        root: Some(tmp.path()),
        ..Place::remotes(&remotes)
    };

    let reg = Registry::new(
        Config::default(),
        vec![
            scoped("web", r, Some("apps/web")),
            scoped("api", r, Some("apps/api")),
        ],
    )
    .unwrap();
    assert_eq!(reg.find(place).unwrap().project.name, name("web"));
    let as_written = Place {
        root: None,
        ..place
    };
    assert!(matches!(
        reg.find(as_written),
        Err(MatchError::NoPathMatches { .. })
    ));

    let reg = Registry::new(
        Config::default(),
        vec![
            scoped("web", r, Some("apps/web")),
            scoped("site", r, Some("packages/web")),
        ],
    )
    .unwrap();
    let err = reg.find(place).unwrap_err();
    assert!(matches!(err, MatchError::SamePath { .. }), "{err:?}");
    assert!(
        err.to_string()
            .contains("web (apps/web) and site (packages/web) are the same folder"),
        "{err}"
    );

    // A symlink out of the checkout, by one `..` too many, is refused
    // rather than matched as written; a missing path still is.
    std::os::unix::fs::symlink("../..", tmp.path().join("apps/out")).unwrap();
    let reg = Registry::new(
        Config::default(),
        vec![
            scoped("web", r, Some("apps/web")),
            scoped("out", r, Some("apps/out")),
        ],
    )
    .unwrap();
    let err = reg.find(place).unwrap_err();
    assert!(
        matches!(&err, MatchError::PathOutsideCheckout { project, .. } if *project == name("out")),
        "{err:?}"
    );
    assert!(err.to_string().contains("apps/out leads outside"), "{err}");
    assert!(matches!(
        reg.find(as_written),
        Err(MatchError::NoPathMatches { .. })
    ));
}

#[test]
fn a_named_project_must_claim_the_checkout() {
    let r = "github.com/acme/mono";
    let reg = Registry::new(
        Config::default(),
        vec![
            scoped("web", r, Some("apps/web")),
            scoped("api", r, Some("apps/api")),
            scoped("other", "github.com/acme/other", None),
        ],
    )
    .unwrap();
    let remotes = ids(&["https://github.com/acme/mono"]);
    let (api, other, nope) = (name("api"), name("other"), name("nope"));
    let named = |n| Place {
        project: Some(n),
        ..at(&remotes, "apps/web")
    };
    // Named wins over the folder, and works where no path matches.
    assert_eq!(reg.find(named(&api)).unwrap().project.name, api);
    let root = Place {
        subdir: None,
        ..named(&api)
    };
    assert_eq!(reg.find(root).unwrap().project.name, api);

    let err = reg.find(named(&other)).unwrap_err();
    assert!(matches!(err, MatchError::NotThisCheckout { .. }), "{err:?}");
    assert_eq!(
        err.to_string(),
        "project other does not claim this checkout's remotes (github.com/acme/mono)"
    );
    let err = reg.find(named(&nope)).unwrap_err();
    assert!(matches!(err, MatchError::NoSuchProject(_)), "{err:?}");
}

#[test]
fn a_tie_across_a_forks_remotes_is_ambiguous() {
    let reg = Registry::new(
        Config::default(),
        vec![
            scoped("mine", "github.com/me/mono", Some("apps/web")),
            scoped("web", "github.com/acme/mono", Some("apps/web")),
        ],
    )
    .unwrap();
    let remotes = ids(&["https://github.com/me/mono", "https://github.com/acme/mono"]);
    let err = reg.find(at(&remotes, "apps/web")).unwrap_err();
    assert!(matches!(err, MatchError::Ambiguous { .. }), "{err:?}");

    // One project claiming both remotes is not a tie.
    let reg = Registry::new(
        Config::default(),
        vec![
            project(
                "web",
                "schema = 1\nremotes = [\"github.com/me/mono\", \"github.com/acme/mono\"]\n\
                 path = \"apps/web\"\n[envs.dev]\n",
            )
            .unwrap(),
        ],
    )
    .unwrap();
    assert_eq!(
        reg.find(at(&remotes, "apps/web")).unwrap().project.name,
        name("web")
    );
}

#[test]
fn subdir_is_found_through_a_symlink() {
    let s = GitSandbox::new();
    let root = s.repo("mono", &[("origin", "git@github.com:acme/mono.git")]);
    fs::create_dir_all(root.join("apps/web/src")).unwrap();
    let link = s.path().join("web-link");
    std::os::unix::fs::symlink(root.join("apps/web"), &link).unwrap();

    let c = s.git().checkout(&link.join("src")).unwrap();
    assert_eq!(
        c.subdir(&link.join("src")).as_deref(),
        Some(Path::new("apps/web/src"))
    );
    assert_eq!(c.subdir(&root).as_deref(), Some(Path::new("")));
    assert_eq!(c.subdir(&s.path()), None);

    let reg = Registry::new(
        Config::default(),
        vec![
            scoped("web", "github.com/acme/mono", Some("apps/web")),
            scoped("api", "github.com/acme/mono", Some("apps/api")),
        ],
    )
    .unwrap();
    let (p, _) = reg.resolve(&s.git(), &link).unwrap();
    assert_eq!(p.name, name("web"));
}

#[test]
fn sensitive_patterns_match_whole_locations() {
    let p = |s: &str| SourcePattern::try_from(s.to_owned()).unwrap();
    let prod = p("*/prod/*");
    for loc in ["widget/prod/", "widget/prod/db", "a/b/prod/c", "/prod/"] {
        assert!(prod.matches(loc), "{loc}");
    }
    for loc in [
        "widget/production/x",
        "prod/x",
        "widget/dev/",
        "widget/prod",
    ] {
        assert!(!prod.matches(loc), "{loc}");
    }
    assert!(p("live").matches("live") && !p("live").matches("alive"));
    assert!(p("*live").matches("go-live") && !p("*live").matches("lively"));
    assert!(p("a*b*c").matches("abc") && p("a*b*c").matches("aXbYc"));
    assert!(!p("a*b*c").matches("acb"));
    // The suffix may not reuse characters a middle part consumed.
    assert!(!p("*ab*ba").matches("aba"));
    // Case is ignored, in the pattern and in the location.
    assert!(prod.matches("widget/PROD/db") && prod.matches("Widget/Prod/"));
    assert!(p("*/LIVE/*").matches("a/live/b"));
}

/// An `aws_sm` source's profile is its own, else the env's, else the
/// project's, else `[aws]` in config.toml, else none; its region is its
/// own, else `[aws]`'s. Other providers never get one.
#[test]
fn aws_sources_resolve_profile_and_region_per_source() {
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]
profile = "proj"

[envs.dev]
profile = "envp"

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/dev/"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "shared/dev"
profile = "shared"
region = "eu-west-3"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "widget/dev/eu"
region = "eu-central-1"

[[envs.dev.sources]]
provider = "file"

[envs.qa]
[[envs.qa.sources]]
provider = "aws_sm"
prefix = "widget/qa/"

[envs.bare]
"#;
    let config = parse_config(
        Path::new("c"),
        "schema = 1\ndefault_provider = \"aws_sm\"\n",
    )
    .unwrap();
    let reg = Registry::new(config, vec![project("widget", text).unwrap()]).unwrap();
    let p = reg.project(&name("widget")).unwrap();
    let got = |e: &str| -> Vec<(Option<String>, Option<String>)> {
        reg.env(p, Some(&env(e)))
            .unwrap()
            .sources
            .iter()
            .map(|s| {
                (
                    s.aws.profile.as_ref().map(|p| p.as_str().to_owned()),
                    s.aws.region.as_ref().map(|r| r.as_str().to_owned()),
                )
            })
            .collect()
    };
    let some = |s: &str| Some(s.to_owned());
    assert_eq!(
        got("dev"),
        [
            (some("envp"), None),
            (some("shared"), some("eu-west-3")),
            (some("envp"), some("eu-central-1")),
            (None, None),
        ]
    );
    // No env profile: the project's. The default source inherits it too.
    assert_eq!(got("qa"), [(some("proj"), None)]);
    assert_eq!(got("bare"), [(some("proj"), None)]);

    // No profile anywhere: the ambient AWS configuration.
    let ambient = text
        .replace("profile = \"proj\"\n", "")
        .replace("profile = \"envp\"\n", "");
    let reg = Registry::new(
        reg.config.clone(),
        vec![project("widget", &ambient).unwrap()],
    )
    .unwrap();
    let p = reg.project(&name("widget")).unwrap();
    let profiles: Vec<_> = reg
        .env(p, Some(&env("dev")))
        .unwrap()
        .sources
        .into_iter()
        .map(|s| s.aws.profile)
        .collect();
    assert_eq!(
        profiles,
        [
            None,
            Some("shared".to_owned().try_into().unwrap()),
            None,
            None
        ]
    );

    // `connect aws` saved defaults: they fill only what nothing else set.
    let config = parse_config(
        Path::new("c"),
        "schema = 1
[aws]
profile = \"conn\"
region = \"us-east-1\"
",
    )
    .unwrap();
    let reg = Registry::new(config, vec![project("widget", &ambient).unwrap()]).unwrap();
    let p = reg.project(&name("widget")).unwrap();
    let got: Vec<_> = reg
        .env(p, Some(&env("dev")))
        .unwrap()
        .sources
        .into_iter()
        .map(|s| s.aws.label())
        .collect();
    assert_eq!(
        got,
        [
            " (profile conn, region us-east-1)",
            " (profile shared, region eu-west-3)",
            " (profile conn, region eu-central-1)",
            "",
        ]
    );
}

#[test]
fn profile_and_region_are_for_aws_sources_only() {
    let source = |provider: &str, body: &str| {
        project(
            "widget",
            &format!(
                "schema = 1\nremotes = [\"github.com/a/b\"]\n[[envs.dev.sources]]\nprovider = \"{provider}\"\n{body}\n"
            ),
        )
    };
    let cases = [
        (
            "file",
            "profile = \"p\"",
            "profile can only be used with provider \"aws_sm\", not \"file\"",
        ),
        (
            "file",
            "secret = \"a.b\"\nregion = \"eu-west-1\"",
            "region can only be used with provider \"aws_sm\", not \"file\"",
        ),
        (
            "proton",
            "secret = \"a\"\nprofile = \"p\"",
            "profile can only be used with provider \"aws_sm\", not \"proton\"",
        ),
        (
            "aws_sm",
            "secret = \"a\"\nregion = \"EU-WEST-1\"",
            "region must be 1 to 32 lowercase letters",
        ),
        (
            "aws_sm",
            "secret = \"a\"\nregion = \"evil.example.com/\"",
            "region must be 1 to 32 lowercase letters",
        ),
        (
            "aws_sm",
            "secret = \"a\"\nregion = \"-x\"",
            "region must be 1 to 32 lowercase letters",
        ),
        (
            "aws_sm",
            "secret = \"a\"\nregion = \"\"",
            "region must be 1 to 32 lowercase letters",
        ),
        (
            "aws_sm",
            "secret = \"a\"\nprofile = \"two words\"",
            "profile must not contain whitespace",
        ),
        // A profile alone is not a selector.
        (
            "aws_sm",
            "profile = \"p\"",
            "a source must set exactly one of secret, secrets or prefix",
        ),
    ];
    for (provider, body, want) in cases {
        let err = source(provider, body).unwrap_err().to_string();
        assert!(err.contains(want), "{provider} {body}: {err}");
    }
    for r in ["us-east-1", "us-gov-west-1", "cn-north-1", "eu-central-2"] {
        assert!(
            source("aws_sm", &format!("prefix = \"a/\"\nregion = \"{r}\"")).is_ok(),
            "{r}"
        );
    }
}

/// The example in docs/project-files.md parses and means what it says.
#[test]
fn the_documented_example_parses() {
    let doc = include_str!("../../../../docs/project-files.md");
    let text = doc
        .split("```toml\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    let reg = Registry::new(Config::default(), vec![project("widget", text).unwrap()]).unwrap();
    let p = reg.project(&name("widget")).unwrap();
    let qa = reg.env(p, Some(&env("qa"))).unwrap();
    let got: Vec<_> = qa
        .sources
        .iter()
        .map(|s| (crate::daemon::resolve::describe(s), s.optional))
        .collect();
    assert_eq!(
        got,
        [
            ("file secret widget.qa".to_owned(), false),
            (
                "aws_sm prefix widget/qa/ (profile widget-qa)".to_owned(),
                false
            ),
            (
                "aws_sm secret platform/qa/shared (profile platform, region eu-west-3)".to_owned(),
                false
            ),
            (
                "aws_sm secret widget/qa/stripe (profile widget-qa)".to_owned(),
                true
            ),
        ]
    );
}
