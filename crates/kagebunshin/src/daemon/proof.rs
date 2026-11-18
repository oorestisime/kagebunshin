//! Proof that an environment works: the last `run --strict` that exited 0,
//! per project and environment.
//!
//! Kept in `proofs.json` beside the audit log, in the daemon's state
//! directory, so it survives a restart. A proof keeps what the audit log
//! keeps of a run (when, and the program's name; never its arguments or a
//! value) and a fingerprint of the environment's sources and plain settings
//! when it was made. It holds only while they are unchanged: a proof whose
//! fingerprint differs from the environment's now is not reported, and the
//! next proof of that environment replaces it.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::config::EnvSettings;
use crate::ipc::protocol::Proof;

const FILE: &str = "proofs.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    time: u64,
    program: String,
    fingerprint: String,
}

pub struct Proofs {
    path: PathBuf,
    /// Held across each read-modify-write of the file.
    write: Mutex<()>,
}

impl Proofs {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            write: Mutex::new(()),
        }
    }

    /// `proofs.json` in the directory of `audit_log`.
    pub fn beside(audit_log: &Path) -> Self {
        Self::new(audit_log.with_file_name(FILE))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The proof of `settings`' environment, if it was made with the
    /// sources and settings it has now. A file that cannot be read has none.
    pub fn get(&self, settings: &EnvSettings<'_>) -> Option<Proof> {
        let all = self.read().ok()?;
        let stored = all.get(&section(settings))?;
        (stored.fingerprint == fingerprint(settings)).then(|| Proof {
            time: stored.time,
            program: stored.program.clone(),
        })
    }

    /// Records that `program` ran with `settings`' environment and exited 0.
    pub fn record(&self, settings: &EnvSettings<'_>, time: u64, program: &str) -> io::Result<()> {
        let _held = self.write.lock().unwrap_or_else(PoisonError::into_inner);
        // A file that does not parse is replaced: it only held proofs.
        let mut all = self.read().unwrap_or_default();
        all.insert(
            section(settings),
            Stored {
                time,
                program: program.to_owned(),
                fingerprint: fingerprint(settings),
            },
        );
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_vec_pretty(&all).map_err(io::Error::other)?;
        crate::atomic::write_private(&self.path, &json)
    }

    fn read(&self) -> io::Result<BTreeMap<String, Stored>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e),
        }
    }
}

fn section(settings: &EnvSettings<'_>) -> String {
    format!("{}.{}", settings.project, settings.env)
}

/// FNV-1a over the sources and plain settings as written out: it changes
/// whenever either does. A change in how they are written out (a new
/// version) only forgets proofs.
fn fingerprint(settings: &EnvSettings<'_>) -> String {
    let text = format!("{:?}\n{:?}", settings.sources, settings.vars);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Registry;
    use crate::config::{Config, parse_project};

    fn registry(vars: &str) -> Registry {
        let toml = format!(
            "schema = 1\nremotes = [\"git@github.com:acme/widget.git\"]\n[envs.dev]\n{vars}\n"
        );
        let p = parse_project(Path::new("/cfg/projects/widget.toml"), &toml).unwrap();
        Registry::new(Config::default(), vec![p]).unwrap()
    }

    #[test]
    fn a_proof_holds_until_the_settings_change() {
        let tmp = tempfile::tempdir().unwrap();
        let proofs = Proofs::new(tmp.path().join("state/proofs.json"));
        let r = registry("");
        let name = "widget".parse().unwrap();
        let settings = r.env(r.project(&name).unwrap(), None).unwrap();
        assert_eq!(proofs.get(&settings), None);
        proofs
            .record(&settings, 1_794_389_173, "./test.sh")
            .unwrap();
        let proof = Proof {
            time: 1_794_389_173,
            program: "./test.sh".into(),
        };
        assert_eq!(proofs.get(&settings), Some(proof.clone()));
        // It survives a restart: a new reader of the same file.
        assert_eq!(
            Proofs::new(proofs.path()).get(&settings),
            Some(proof.clone())
        );

        let changed = registry("vars = { PORT = \"3000\" }");
        let settings = changed.env(changed.project(&name).unwrap(), None).unwrap();
        assert_eq!(proofs.get(&settings), None);
    }

    #[test]
    fn a_broken_file_has_no_proofs_and_is_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("proofs.json");
        std::fs::write(&path, "not json").unwrap();
        let proofs = Proofs::new(&path);
        let r = registry("");
        let settings = r
            .env(r.project(&"widget".parse().unwrap()).unwrap(), None)
            .unwrap();
        assert_eq!(proofs.get(&settings), None);
        proofs.record(&settings, 1, "make").unwrap();
        assert_eq!(
            proofs.get(&settings).map(|p| p.program),
            Some("make".into())
        );
    }
}
