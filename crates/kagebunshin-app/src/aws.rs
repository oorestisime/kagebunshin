//! Connecting AWS from the window, the way `kagebunshin connect aws` does
//! at a terminal, on a thread of its own: check the profile can list
//! secrets, log it in with `aws [sso] login` if its credentials are missing
//! or expired, and check again. Connecting saves it as `[aws]` in
//! `config.toml`, the profile AWS sources that name none use; logging in
//! leaves that as it is. The AWS CLI's output shows in the window as it
//! comes, and cancelling stops it. No value passes through here: the AWS
//! CLI keeps the credentials it gets.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kagebunshin::config::schema::{Profile, Region};
use kagebunshin::config::{AwsSettings, ConfigDir};
use kagebunshin::source::Health;
use kagebunshin::source::aws_sm::connect;
use rune::Waker;

use crate::daemon::Problem;

/// A login under way, or done.
pub struct Login {
    shared: Arc<Mutex<Shared>>,
}

#[derive(Default)]
struct Shared {
    /// What it did, and the AWS CLI's output, a line each.
    lines: Vec<String>,
    /// The AWS CLI, while it runs.
    child: Option<Child>,
    cancelled: bool,
    /// How it ended: what to say, or why it failed.
    outcome: Option<Result<String, Problem>>,
    /// Something changed since the window last looked.
    fresh: bool,
}

impl Login {
    /// Starts on its own thread. `dir` is where `[aws]` is saved, needed
    /// only when `save` is set.
    pub fn start(
        profile: Profile,
        region: Option<Region>,
        save: bool,
        dir: Result<ConfigDir, String>,
        waker: Waker,
    ) -> Result<Self, Problem> {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let login = Self {
            shared: shared.clone(),
        };
        std::thread::Builder::new()
            .name("kagebunshin-aws-login".into())
            .spawn(move || {
                let outcome = run(&shared, &waker, &profile, region, save, dir);
                let mut sh = lock(&shared);
                // A success stands: [`finish`] saw no cancel before saving.
                sh.outcome = Some(match outcome {
                    Err(_) if sh.cancelled => Err(Problem::new("Cancelled.")),
                    o => o,
                });
                sh.fresh = true;
                drop(sh);
                waker();
            })
            .map_err(|e| Problem::new(format!("cannot start the AWS login thread: {e}")))?;
        Ok(login)
    }

    pub fn lines(&self) -> Vec<String> {
        lock(&self.shared).lines.clone()
    }

    /// `None` while it runs.
    pub fn outcome(&self) -> Option<Result<String, Problem>> {
        lock(&self.shared).outcome.clone()
    }

    /// Whether anything changed since this was last asked.
    pub fn fresh(&self) -> bool {
        std::mem::take(&mut lock(&self.shared).fresh)
    }

    /// Stops the AWS CLI if it runs, and the check after it.
    pub fn cancel(&self) {
        let mut sh = lock(&self.shared);
        sh.cancelled = true;
        if let Some(child) = &mut sh.child {
            // Already gone is fine: it ends either way.
            let _ = child.kill();
        }
    }
}

impl Drop for Login {
    /// A window closed mid-login leaves no AWS CLI behind.
    fn drop(&mut self) {
        if self.outcome().is_none() {
            self.cancel();
        }
    }
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

fn say(shared: &Mutex<Shared>, waker: &Waker, line: String) {
    let mut sh = lock(shared);
    sh.lines.push(line);
    sh.fresh = true;
    drop(sh);
    waker();
}

fn run(
    shared: &Arc<Mutex<Shared>>,
    waker: &Waker,
    profile: &Profile,
    region: Option<Region>,
    save: bool,
    dir: Result<ConfigDir, String>,
) -> Result<String, Problem> {
    say(
        shared,
        waker,
        format!("Checking that AWS profile {profile} can list secrets…"),
    );
    let mut health = connect::check(profile, region.as_ref());
    if let Health::NeedsLogin { .. } = &health {
        login(shared, waker, profile)?;
        if lock(shared).cancelled {
            return Err(Problem::new("Cancelled."));
        }
        say(shared, waker, "Checking again…".into());
        health = connect::check(profile, region.as_ref());
    }
    match health {
        Health::Ok => {}
        Health::NeedsLogin { hint } => {
            return Err(Problem::new(format!(
                "the credentials of AWS profile {profile} are still missing or expired"
            ))
            .with_hint(hint));
        }
        Health::NotConnected { hint } => {
            return Err(Problem::new("AWS is not connected").with_hint(hint));
        }
        // AWS reads no store.
        Health::Locked => return Err(Problem::new("the daemon is locked")),
        Health::Failed { message } => {
            return Err(Problem::new(format!(
                "AWS profile {profile} cannot list secrets: {message}"
            )));
        }
    }
    finish(shared, profile, region, save, dir)
}

/// The last step, once the profile can list secrets: saves it as `[aws]`
/// when `save` is set, unless cancelled. The cancel check and the save are
/// made under one lock, so a cancel lands either before the save, which it
/// stops, or after it.
fn finish(
    shared: &Mutex<Shared>,
    profile: &Profile,
    region: Option<Region>,
    save: bool,
    dir: Result<ConfigDir, String>,
) -> Result<String, Problem> {
    let sh = lock(shared);
    if sh.cancelled {
        return Err(Problem::new("Cancelled."));
    }
    if !save {
        return Ok(format!("AWS profile {profile} can list secrets."));
    }
    let settings = AwsSettings {
        profile: Some(profile.clone()),
        region: region.clone(),
    };
    let dir = dir.map_err(Problem::new)?;
    connect::save(&dir, &settings).map_err(Problem::new)?;
    drop(sh);
    let region = region.map(|r| format!(" in {r}")).unwrap_or_default();
    Ok(format!(
        "Connected AWS profile {profile}{region}: AWS sources that name no profile now use it."
    ))
}

/// Runs `aws [sso] login --profile P`, its output piped into the window.
fn login(shared: &Arc<Mutex<Shared>>, waker: &Waker, profile: &Profile) -> Result<(), Problem> {
    let set = connect::profiles();
    let mut cmd = connect::login_command(set.as_ref(), profile);
    let args: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    say(shared, waker, format!("$ aws {}", args.join(" ")));
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| {
        Problem::new(format!("cannot run the AWS CLI: {e}")).with_hint(
            "install it: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
        )
    })?;
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    {
        let mut sh = lock(shared);
        if sh.cancelled {
            let _ = child.kill();
        }
        sh.child = Some(child);
    }
    // stderr on a thread of its own, so neither pipe fills while the other
    // is read.
    let errors = stderr.map(|e| {
        let (shared, waker) = (Arc::clone(shared), waker.clone());
        std::thread::Builder::new()
            .name("kagebunshin-aws-stderr".into())
            .spawn(move || read_lines(e, |l| say(&shared, &waker, l)))
    });
    if let Some(out) = stdout {
        read_lines(out, |l| say(shared, waker, l));
    }
    let spawned = match errors {
        Some(Ok(reader)) => reader.join().is_ok(),
        Some(Err(_)) => false,
        None => true,
    };
    let child = lock(shared).child.take();
    let Some(mut child) = child else {
        return Err(Problem::new("the AWS CLI did not start"));
    };
    if !spawned {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|e| Problem::new(format!("cannot wait for the AWS CLI: {e}")))?;
    if !spawned {
        return Err(Problem::new("cannot read the AWS CLI's output"));
    }
    if status.success() || lock(shared).cancelled {
        Ok(())
    } else {
        Err(Problem::new(format!("aws login failed ({status})")))
    }
}

fn read_lines(from: impl Read, mut each: impl FnMut(String)) {
    for line in BufReader::new(from).lines() {
        match line {
            Ok(l) if l.trim().is_empty() => {}
            Ok(l) => each(l),
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cancel that arrives after the last check, before the save, still
    /// stops it: the default profile is left as it was.
    #[test]
    fn a_cancel_before_the_save_stops_it() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = ConfigDir::new(tmp.path());
        let profile = Profile::try_from("acme".to_owned()).unwrap();
        let shared = Mutex::new(Shared {
            cancelled: true,
            ..Shared::default()
        });
        let r = finish(&shared, &profile, None, true, Ok(dir.clone()));
        assert!(r.is_err(), "{r:?}");
        assert!(!dir.config_file().exists(), "not saved");

        lock(&shared).cancelled = false;
        finish(&shared, &profile, None, true, Ok(dir.clone())).unwrap();
        assert!(dir.config_file().exists(), "saved when not cancelled");
    }
}
