//! The environment keys a checkout's code reads, by name: found in the text
//! of its files, with nothing run and nothing sent anywhere.
//!
//! [`reads`] looks for the ways code names a key it takes from its
//! environment:
//!
//! - JavaScript and TypeScript, and Svelte, Vue and Astro files: `env.KEY`,
//!   `env["KEY"]` and `env.get("KEY")` on anything called `env`
//!   (`process.env`, `import.meta.env`, `Bun.env`, `Deno.env`, a Worker's
//!   `env`), `const { KEY } = process.env`, and the property names of a
//!   typed env module, a file called `env.*`. Only names in capitals.
//! - Python: `environ["KEY"]`, `environ.get("KEY")`, `getenv("KEY")`.
//! - Rust: `env::var("KEY")`, `env::var_os("KEY")`, `env!("KEY")`,
//!   `option_env!("KEY")`.
//! - A Wrangler config (`wrangler.toml`, `.json`, `.jsonc`): the names of
//!   `secrets.required`. Its `vars` and its bindings (a KV namespace, a
//!   database, a queue) are in a Worker's `env` too, but the config gives
//!   them itself, so those names are left out.
//!
//! Names the platform or the toolchain sets ([`PLATFORM`]) are left out
//! too. The result is a seed for `.env.example`, to be checked against the
//! code: a key read through a variable, a settings class or another
//! language is not found, and a name in a comment is.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use super::facts::{MAX_FILE_SIZE, MAX_FILES, SKIP};
use super::{ENV_EXAMPLE, is_real_env_file};
use crate::types::KeyName;

/// Names reported at most.
pub const MAX_KEYS: usize = 200;

/// Names the operating system, the toolchain or the host sets, which no
/// secret store holds.
const PLATFORM: &[&str] = &[
    "CI",
    "DISPLAY",
    "EDITOR",
    "FORCE_COLOR",
    "GITHUB_ACTIONS",
    "HOME",
    "HOSTNAME",
    "LANG",
    "NEXT_RUNTIME",
    "NODE_ENV",
    "NO_COLOR",
    "PATH",
    "PWD",
    "SHELL",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "TZ",
    "USER",
    "VERCEL",
    "VERCEL_ENV",
    "VERCEL_REGION",
    "VERCEL_URL",
];
const PLATFORM_PREFIXES: &[&str] = &[
    "CARGO_",
    "CF_PAGES",
    "KAGEBUNSHIN_",
    "LC_",
    "RUNNER_",
    "VERCEL_GIT_",
    "XDG_",
    "npm_",
];
/// What Vite itself puts in `import.meta.env`.
const VITE: &[&str] = &["BASE_URL", "DEV", "MODE", "PROD", "SSR"];

const WRANGLER: &[&str] = &["wrangler.toml", "wrangler.json", "wrangler.jsonc"];
const JS: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts", "svelte", "vue", "astro",
];
const PYTHON: &[&str] = &["environ[", "environ.get(", "getenv("];
const RUST: &[&str] = &["env::var(", "env::var_os(", "env!(", "option_env!("];

/// The keys the code reads.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Reads {
    /// By name; each with the files, relative to the root, that name it.
    pub keys: Vec<Read>,
    /// The caps that were hit, in words.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capped: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Read {
    pub key: KeyName,
    pub files: Vec<PathBuf>,
}

/// The keys that `files` (relative to `root`, as git lists them) read from
/// the environment; see the module docs. Real env files, big files, binary
/// files and folders of dependencies or build output are skipped.
pub fn reads(root: &Path, files: &[PathBuf]) -> Reads {
    let mut out = Reads::default();
    let mut found: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    // What a Wrangler config gives a Worker itself.
    let mut given: BTreeSet<String> = BTreeSet::new();
    let mut searched = 0;
    for rel in files {
        let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let skipped = (rel.parent().into_iter())
            .flat_map(Path::components)
            .any(|c| c.as_os_str().to_str().is_some_and(|c| SKIP.contains(&c)));
        if skipped || is_real_env_file(name.as_ref()) || name == ENV_EXAMPLE {
            continue;
        }
        let wrangler = WRANGLER.contains(&name);
        let ext = rel.extension().and_then(|e| e.to_str()).unwrap_or_default();
        if !wrangler && !JS.contains(&ext) && ext != "py" && ext != "rs" {
            continue;
        }
        if searched == MAX_FILES {
            out.capped
                .push(format!("searched only {MAX_FILES} of the checkout's files"));
            break;
        }
        let Some(text) = text_of(&root.join(rel)) else {
            continue;
        };
        searched += 1;
        let mut names = BTreeSet::new();
        if wrangler {
            wrangler_names(name, &text, &mut names, &mut given);
        } else if ext == "py" {
            called(&text, PYTHON, &mut names);
        } else if ext == "rs" {
            called(&text, RUST, &mut names);
        } else {
            js_names(&text, &mut names);
            if name.split('.').next() == Some("env") {
                typed_module(&text, &mut names);
            }
        }
        for n in names {
            found.entry(n).or_default().push(rel.clone());
        }
    }
    out.keys = found
        .into_iter()
        .filter(|(name, _)| !given.contains(name) && !platform(name))
        .filter_map(|(name, files)| {
            Some(Read {
                key: name.parse().ok()?,
                files,
            })
        })
        .collect();
    if out.keys.len() > MAX_KEYS {
        out.capped.push(format!(
            "kept only the first {MAX_KEYS} of {} names",
            out.keys.len()
        ));
        out.keys.truncate(MAX_KEYS);
    }
    out
}

fn platform(name: &str) -> bool {
    PLATFORM.contains(&name) || PLATFORM_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The text of a regular file that is not big and not binary.
fn text_of(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_SIZE {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

/// The identifier `text` starts with, if it is a name in capitals:
/// `API_KEY`, not `apiKey` and not `Env`.
fn capitals(text: &str) -> Option<&str> {
    let end = text.find(|c| !ident(c)).unwrap_or(text.len());
    let name = &text[..end];
    let ok = name.len() > 1
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && (name.chars()).all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    ok.then_some(name)
}

/// The name in the string literal `text` starts with, after any space:
/// `"API_KEY"`. A string that is not a variable's name is none.
fn quoted(text: &str) -> Option<&str> {
    let text = text.trim_start();
    let quote = text.chars().next().filter(|c| "\"'`".contains(*c))?;
    let (name, _) = text[1..].split_once(quote)?;
    let ok = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    ok.then_some(name)
}

/// The names in string literals right after one of `calls`:
/// `getenv("API_KEY")`.
fn called(text: &str, calls: &[&str], out: &mut BTreeSet<String>) {
    for call in calls {
        for (at, _) in text.match_indices(call) {
            out.extend(quoted(&text[at + call.len()..]).map(str::to_owned));
        }
    }
}

/// What JavaScript reads from anything called `env`.
fn js_names(text: &str, out: &mut BTreeSet<String>) {
    for (at, _) in text.match_indices("env") {
        let before = &text[..at];
        if before.ends_with(ident) {
            continue;
        }
        let rest = &text[at + 3..];
        let name = if let Some(member) = rest.strip_prefix('.') {
            match member.strip_prefix("get(") {
                Some(arg) => quoted(arg).and_then(capitals),
                None => capitals(member),
            }
        } else if let Some(index) = rest.strip_prefix('[') {
            quoted(index).and_then(capitals)
        } else {
            if !rest.starts_with(ident) {
                destructured(before, out);
            }
            None
        };
        let vite = before.ends_with("import.meta.");
        out.extend(
            name.filter(|n| !(vite && VITE.contains(n)))
                .map(str::to_owned),
        );
    }
}

/// The names taken apart from an `env`, where `before` is the text up to
/// it: `const { API_KEY, PORT: port, HOST = "x" } = process.`.
fn destructured(before: &str, out: &mut BTreeSet<String>) {
    let before = before.trim_end_matches(|c| ident(c) || c == '.');
    let Some(before) = before.trim_end().strip_suffix('=') else {
        return;
    };
    let Some(before) = before.trim_end().strip_suffix('}') else {
        return;
    };
    let Some((_, names)) = before.rsplit_once('{') else {
        return;
    };
    out.extend(
        names
            .split(',')
            .filter_map(|n| capitals(n.trim_start()))
            .map(str::to_owned),
    );
}

/// The property names of a typed env module, one to a line:
/// `API_KEY: string().optional(),` or `readonly API_KEY?: string`.
fn typed_module(text: &str, out: &mut BTreeSet<String>) {
    for line in text.lines() {
        let line = line.trim_start();
        let line = line.strip_prefix("readonly ").unwrap_or(line).trim_start();
        let Some(name) = capitals(line) else {
            continue;
        };
        let rest = line[name.len()..].trim_start();
        if rest.strip_prefix('?').unwrap_or(rest).starts_with(':') {
            out.insert(name.to_owned());
        }
    }
}

/// From Wrangler config `text`, in file `name`: the secrets it says the
/// Worker needs, into `read`, and the names it gives the Worker itself,
/// its `vars` and bindings, into `given`. One that does not parse says
/// nothing.
fn wrangler_names(
    name: &str,
    text: &str,
    read: &mut BTreeSet<String>,
    given: &mut BTreeSet<String>,
) {
    let config: Option<Value> = if name == "wrangler.toml" {
        toml::from_str(text).ok()
    } else {
        serde_json::from_str(&plain_json(text)).ok()
    };
    let Some(config) = config else {
        return;
    };
    // The top level, and each of its `env.<name>` tables.
    let envs = config.get("env").and_then(Value::as_object);
    let tables = std::iter::once(&config).chain(envs.into_iter().flat_map(|e| e.values()));
    for table in tables {
        if let Some(vars) = table.get("vars").and_then(Value::as_object) {
            given.extend(vars.keys().cloned());
        }
        let required = table
            .get("secrets")
            .and_then(|s| s.get("required"))
            .and_then(Value::as_array);
        let required = required.into_iter().flatten().filter_map(Value::as_str);
        read.extend(required.map(str::to_owned));
    }
    bindings(&config, false, given);
}

/// The names `config` binds a resource to: every `binding`, and the `name`
/// of the entries of a `bindings` or `send_email` list (`named`).
fn bindings(config: &Value, named: bool, given: &mut BTreeSet<String>) {
    match config {
        Value::Object(fields) => {
            for (key, value) in fields {
                match (key.as_str(), value) {
                    ("binding", Value::String(name)) => {
                        given.insert(name.clone());
                    }
                    ("name", Value::String(name)) if named => {
                        given.insert(name.clone());
                    }
                    _ => bindings(
                        value,
                        matches!(key.as_str(), "bindings" | "send_email"),
                        given,
                    ),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                bindings(item, named, given);
            }
        }
        _ => {}
    }
}

/// JSON with comments and trailing commas, as Wrangler takes it, made
/// plain JSON.
fn plain_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                '\\' => out.extend(chars.next()),
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match (c, chars.peek()) {
            ('"', _) => {
                in_string = true;
                out.push(c);
            }
            ('/', Some('/')) => {
                if chars.by_ref().any(|c| c == '\n') {
                    out.push('\n');
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut star = false;
                for c in chars.by_ref() {
                    if star && c == '/' {
                        break;
                    }
                    star = c == '*';
                }
            }
            ('}' | ']', _) => {
                // A comma with only space after it is a trailing one.
                let kept = out.trim_end().len();
                if out[..kept].ends_with(',') {
                    out.truncate(kept - 1);
                }
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, text: &str) -> PathBuf {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
        PathBuf::from(rel)
    }

    fn names(reads: &Reads) -> Vec<&str> {
        reads.keys.iter().map(|r| r.key.as_str()).collect()
    }

    fn in_js(text: &str) -> Vec<String> {
        let mut out = BTreeSet::new();
        js_names(text, &mut out);
        out.into_iter().collect()
    }

    #[test]
    fn javascript_reads_of_anything_called_env() {
        assert_eq!(
            in_js(
                "const a = process.env.API_KEY;\n\
                 const b = process.env['DB_URL'] ?? import.meta.env.VITE_SITE;\n\
                 if (import.meta.env.DEV) {}\n\
                 const c = Deno.env.get(\"QUEUE_URL\"), d = Bun.env.BUN_KEY;\n\
                 export default { fetch(req, env) { return env.SIGNING_KEY + c.env.HONO_KEY } };\n"
            ),
            [
                "API_KEY",
                "BUN_KEY",
                "DB_URL",
                "HONO_KEY",
                "QUEUE_URL",
                "SIGNING_KEY",
                "VITE_SITE"
            ]
        );
        // Not a name in capitals, not `env` as a whole word, not a read.
        assert!(
            in_js(
                "process.env.apiKey; myenv.API_KEY; env.Key; environment.API_KEY; \
                 process.env[name]; env.get(name); env.X"
            )
            .is_empty()
        );
    }

    #[test]
    fn javascript_names_taken_apart_from_env() {
        assert_eq!(
            in_js(
                "const { API_KEY, PORT: port, HOST = 'x', ...rest } = process.env;\n\
                 const {\n  DB_URL,\n  lower,\n} = env\n\
                 const env = process.env;\n\
                 if (a === env) {}\n"
            ),
            ["API_KEY", "DB_URL", "HOST", "PORT"]
        );
    }

    #[test]
    fn a_typed_env_module_lists_its_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let files = [
            write(
                root,
                "env.ts",
                "export default defineEnv({\n  /** Doc. */\n  API_KEY: string(),\n  \
                 DEV_LOGIN: boolean().default(false),\n  server: {\n    DB_URL: z.string(),\n  \
                 },\n});\n",
            ),
            write(
                root,
                "src/env.d.ts",
                "interface ImportMetaEnv {\n  readonly VITE_SITE: string;\n  readonly \
                 VITE_FLAG?: string;\n}\n",
            ),
            // Not an env module: its properties are not keys.
            write(
                root,
                "src/config.ts",
                "export const c = {\n  MAX_SIZE: 3,\n};\n",
            ),
        ];
        assert_eq!(
            names(&reads(root, &files)),
            ["API_KEY", "DB_URL", "DEV_LOGIN", "VITE_FLAG", "VITE_SITE"]
        );
    }

    #[test]
    fn python_and_rust_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let files = [
            write(
                root,
                "app/settings.py",
                "import os\nA = os.environ[\"DB_URL\"]\nB = os.environ.get('API_KEY', '')\n\
                 C = os.getenv(\"queue_url\")\nD = os.environ.get(name)\nE = os.getenv('HOME')\n",
            ),
            write(
                root,
                "src/main.rs",
                "fn main() {\n    let a = std::env::var(\"SIGNING_KEY\");\n    let b = \
                 env::var_os( \"TOKEN\" );\n    let v = env!(\"CARGO_PKG_VERSION\");\n    let c = \
                 option_env!(\"BUILD_ID\");\n    let d = env::var(name);\n}\n",
            ),
            // No language looked at.
            write(root, "README.md", "Set process.env.NOT_READ first.\n"),
            write(root, "node_modules/x/index.js", "process.env.NOT_OURS\n"),
        ];
        let found = reads(root, &files);
        assert_eq!(
            names(&found),
            [
                "API_KEY",
                "BUILD_ID",
                "DB_URL",
                "SIGNING_KEY",
                "TOKEN",
                "queue_url"
            ]
        );
        assert_eq!(found.keys[0].files, [Path::new("app/settings.py")]);
    }

    #[test]
    fn a_wrangler_config_names_secrets_and_what_it_gives_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let worker = "export default { fetch(req, env) {\n  env.DB.prepare('x');\n  return \
                      env.API_KEY + env.SITE_URL + env.CACHE.get('k') + env.ROOM + env.MAIL + \
                      env.STAGE_ONLY;\n} };\n";
        let jsonc = r#"{
  // A comment, and "one" in a string: "//".
  "name": "worker", /* another */
  "vars": { "SITE_URL": "https://example.com", },
  "secrets": { "required": ["API_KEY", "SIGNING_KEY"] },
  "kv_namespaces": [{ "binding": "CACHE", "id": "x" },],
  "d1_databases": [{ "binding": "DB", "database_name": "d" }],
  "durable_objects": { "bindings": [{ "name": "ROOM", "class_name": "Room" }] },
  "send_email": [{ "name": "MAIL" }],
  "env": { "staging": { "vars": { "STAGE_ONLY": "1" }, "secrets": { "required": ["STAGE_KEY"] } } },
}"#;
        let files = [
            write(root, "src/index.ts", worker),
            write(root, "wrangler.jsonc", jsonc),
        ];
        assert_eq!(
            names(&reads(root, &files)),
            ["API_KEY", "SIGNING_KEY", "STAGE_KEY"]
        );

        let toml = "name = \"worker\"\n[vars]\nSITE_URL = \"x\"\n[secrets]\nrequired = \
                    [\"API_KEY\"]\n[[kv_namespaces]]\nbinding = \"CACHE\"\n[[d1_databases]]\n\
                    binding = \"DB\"\n[[durable_objects.bindings]]\nname = \"ROOM\"\n\
                    class_name = \"Room\"\n[[send_email]]\nname = \"MAIL\"\n";
        fs::remove_file(root.join("wrangler.jsonc")).unwrap();
        let files = [
            write(root, "src/index.ts", worker),
            write(root, "wrangler.toml", toml),
        ];
        assert_eq!(names(&reads(root, &files)), ["API_KEY", "STAGE_ONLY"]);
    }

    #[test]
    fn env_files_and_platform_names_are_left_out() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let files = [
            write(
                root,
                "src/a.js",
                "process.env.NODE_ENV; process.env.CI; process.env.VERCEL_GIT_COMMIT_SHA; \
                 process.env.VERCEL_TOKEN; process.env.npm_package_version;",
            ),
            // A real env file is never opened, whatever its extension.
            write(root, ".env.js", "process.env.FROM_ENV_FILE"),
        ];
        assert_eq!(names(&reads(root, &files)), ["VERCEL_TOKEN"]);
    }

    #[test]
    fn caps_are_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let lines: Vec<String> = (0..=MAX_KEYS)
            .map(|i| format!("process.env.KEY_{i};"))
            .collect();
        let text = lines.join("\n");
        let found = reads(root, &[write(root, "a.js", &text)]);
        assert_eq!(found.keys.len(), MAX_KEYS);
        assert_eq!(found.capped.len(), 1);
    }
}
