//! Connecting AWS, the parts that need no terminal: the profiles in the AWS
//! configuration, checking that one can list secrets, the `aws` command that
//! logs it in, and saving it as `[aws]` in `config.toml`. `kagebunshin
//! connect aws` and the app both use these; each asks the human its own way.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use toml_edit::{DocumentMut, Item, Table, value};

use super::AwsBackend;
use super::sdk::SdkSm;
use crate::config::schema::{Profile, Region};
use crate::config::{AwsSettings, Config, ConfigDir};
use crate::source::{Backend, Health};

/// The AWS configuration (`~/.aws/config` and `~/.aws/credentials`, or
/// where `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` point), or
/// `None` if it cannot be read.
pub fn profiles() -> Option<aws_config::profile::ProfileSet> {
    use aws_runtime::env_config::file::EnvConfigFiles;
    use aws_types::os_shim_internal::{Env, Fs};
    let runtime = tokio::runtime::Builder::new_current_thread().build().ok()?;
    runtime
        .block_on(aws_config::profile::load(
            &Fs::real(),
            &Env::real(),
            &EnvConfigFiles::default(),
            None,
        ))
        .ok()
}

/// Every profile name in `set`, sorted.
pub fn profile_names(set: Option<&aws_config::profile::ProfileSet>) -> Vec<String> {
    let mut names: Vec<String> = set
        .iter()
        .flat_map(|s| s.profiles().map(str::to_owned))
        .collect();
    names.sort();
    names
}

/// `aws sso login --profile P` for an SSO profile, else `aws login
/// --profile P`. The caller runs it, at a terminal or with its output
/// piped.
pub fn login_command(set: Option<&aws_config::profile::ProfileSet>, profile: &Profile) -> Command {
    let sso = set
        .and_then(|s| s.get_profile(profile.as_str()))
        .is_some_and(|p| p.get("sso_session").is_some() || p.get("sso_start_url").is_some());
    let mut cmd = Command::new("aws");
    if sso {
        cmd.arg("sso");
    }
    cmd.arg("login").arg("--profile").arg(profile.as_str());
    cmd
}

/// Whether `profile`, in `region` or its own, can list secrets. Blocks on
/// its own runtime, so it runs off any async one: a CLI or a worker thread.
pub fn check(profile: &Profile, region: Option<&Region>) -> Health {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            return Health::Failed {
                message: format!("cannot start a runtime: {e}"),
            };
        }
    };
    let settings = AwsSettings {
        profile: Some(profile.clone()),
        region: region.cloned(),
    };
    runtime.block_on(async {
        let api = SdkSm::load(Some(profile.as_str()), region.map(Region::as_str)).await;
        AwsBackend::new(Arc::new(api), settings)
            .status()
            .await
            .health
    })
}

/// Writes `[aws]` into `config.toml`, keeping everything else in it as it
/// is, comments too. Checked as the daemon would read it before it is
/// written. The error is a message naming the file.
pub fn save(dir: &ConfigDir, settings: &AwsSettings) -> Result<PathBuf, String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .create(dir.path())
        .map_err(|e| format!("cannot create {}: {e}", dir.path().display()))?;
    let _lock = dir
        .lock()
        .map_err(|e| format!("cannot lock {}: {e}", dir.path().display()))?;
    let path = dir.config_file();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "schema = 1\n".to_owned(),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut table = Table::new();
    if let Some(p) = &settings.profile {
        table.insert("profile", value(p.as_str()));
    }
    if let Some(r) = &settings.region {
        table.insert("region", value(r.as_str()));
    }
    doc.insert("aws", Item::Table(table));
    let text = doc.to_string();
    toml::from_str::<Config>(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    crate::atomic::write_private(&path, text.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}
